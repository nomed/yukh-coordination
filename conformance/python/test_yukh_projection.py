from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from yukh_projection import (
    ReplayEngine,
    TranscriptError,
    canonical_json,
    event_digest,
    load_transcript,
    main,
    replay,
    transcript_id,
)


IDS = [f"01989f0e-56b7-7e01-915e-a7748f7f62{i:02x}" for i in range(40)]
CHANNEL = "https://coord.example/channels/project-release"
WORK = "https://github.com/nomed/example/issues/42"


def event(index: int, kind: str, data: dict, *, correlation: str, causation: str | None = None, participant: str = "session:a") -> dict:
    value = {
        "specversion": "0.1",
        "id": IDS[index],
        "type": kind,
        "channel": CHANNEL,
        "source": "https://client.example/session/a",
        "participant": {"id": participant, "kind": "session"},
        "work": {"uri": WORK},
        "time": "2026-08-02T16:00:00.000Z",
        "correlation_id": correlation,
        "data": data,
        "evidence": [],
        "extensions": {},
    }
    if causation is not None:
        value["causation_id"] = causation
    return value


def receipt(value: dict, sequence: int, *, instance: str = IDS[30]) -> dict:
    return {
        "specversion": "0.1",
        "receipt_version": "0.1",
        "receipt_id": IDS[20 + sequence],
        "event_id": value["id"],
        "tenant_id": "tenant:example",
        "channel_id": "channel:project-release",
        "channel_uri": CHANNEL,
        "principal_id": "principal:example",
        "participant_id": value["participant"]["id"],
        "participant_instance_id": instance,
        "session_epoch": 1,
        "cursor": f"cursor-{sequence}",
        "transcript_epoch": 0,
        "sequence": sequence,
        "accepted_at": "2026-08-02T16:00:00.123Z",
        "event_digest": event_digest(value),
        "channel_metadata_digest": "sha-256:" + "1" * 64,
        "acl_policy_version": "acl-v1",
        "acl_policy_digest": "sha-256:" + "2" * 64,
        "acl_decision_receipt_id": "decision-1",
        "append_outcome": "appended",
        "key_id": "relay-key-1",
        "signature_algorithm": "ed25519",
        "signature": "A" * 86,
    }


def record(value: dict, sequence: int, *, instance: str = IDS[30]) -> dict:
    return {"event": value, "receipt": receipt(value, sequence, instance=instance)}


def transcript(records: list[dict], *, high_water: int | None = None, completeness: str = "complete", lifecycle: str = "active") -> dict:
    return {
        "metadata": {
            "tenant_id": "tenant:example",
            "channel_id": "channel:project-release",
            "channel_uri": CHANNEL,
        },
        "transcript_epoch": 0,
        "completeness": completeness,
        "lifecycle": lifecycle,
        "high_water_sequence": high_water if high_water is not None else max(item["receipt"]["sequence"] for item in records),
        "records": records,
    }


def claim(index: int, claim_id: str, expected: list[str] | None = None, predecessor: str | None = None) -> dict:
    data = {
        "claim_id": claim_id,
        "generation": "0",
        "scope": "implementation",
        "boundary": "bounded test work",
        "expected_active_claims": expected or [],
    }
    if predecessor is not None:
        data["predecessor_handoff_event"] = predecessor
    return event(index, "claim", data, correlation=IDS[index], causation=predecessor)


class ReplayTests(unittest.TestCase):
    def test_claim_duplicate_conflict_and_release(self) -> None:
        a = claim(0, IDS[10])
        b = claim(1, IDS[11], [IDS[10]])
        release_b = event(2, "release", {
            "claim_id": IDS[11], "generation": "0", "parent_claim_event_id": b["id"], "outcome": "withdrawn",
        }, correlation=b["id"], causation=b["id"])

        conflict = replay(transcript([record(a, 1), record(a, 1), record(b, 2)]))[0]
        self.assertEqual("conflicting", conflict["state"])
        self.assertEqual([IDS[10], IDS[11]], conflict["contenders"])
        self.assertEqual("CLAIM_CONFLICT", conflict["diagnostics"][0]["code"])
        self.assertEqual(2, conflict["diagnostics"][0]["sequence"])

        resolved = replay(transcript([record(a, 1), record(b, 2), record(release_b, 3)]))[0]
        self.assertEqual("claimed", resolved["state"])
        self.assertEqual([], resolved["diagnostics"])

    def test_handoff_accept_and_successor_claim(self) -> None:
        source = claim(0, IDS[10])
        offer = event(1, "handoff_offer", {
            "handoff_id": IDS[12], "claim_id": IDS[10], "generation": "0",
            "parent_claim_event_id": source["id"], "to_participant_instance_id": IDS[31],
            "boundary": "bounded test work", "boundary_digest": "sha-256:" + "3" * 64,
            "evidence_set_digest": "sha-256:" + "4" * 64, "next_action": "continue", "unresolved_risks": [],
        }, correlation=source["id"], causation=source["id"])
        accept = event(2, "handoff_accept", {
            "handoff_id": IDS[12], "offer_event_id": offer["id"], "source_claim_event_id": source["id"],
            "claim_id": IDS[10], "generation": "0", "boundary_digest": "sha-256:" + "3" * 64,
            "evidence_set_digest": "sha-256:" + "4" * 64,
        }, correlation=source["id"], causation=offer["id"], participant="session:b")

        projected = replay(transcript([record(source, 1), record(offer, 2), record(accept, 3, instance=IDS[31])]))[0]
        self.assertEqual("claimed", projected["state"])
        self.assertEqual("HANDOFF_ACCEPTED_UNCLAIMED", projected["diagnostics"][0]["code"])

        successor = claim(3, IDS[13], predecessor=accept["id"])
        projected = replay(transcript([
            record(source, 1), record(offer, 2), record(accept, 3, instance=IDS[31]), record(successor, 4, instance=IDS[31]),
        ]))[0]
        self.assertEqual("conflicting", projected["state"])
        self.assertNotIn("HANDOFF_ACCEPTED_UNCLAIMED", [item["code"] for item in projected["diagnostics"]])

    def test_incomplete_and_redacted_are_non_final(self) -> None:
        value = claim(0, IDS[10])
        projected = replay(transcript([record(value, 1)], high_water=2, lifecycle="redacted"))[0]
        self.assertEqual("incomplete", projected["completeness"])
        self.assertFalse(projected["final"])
        self.assertEqual(["INCOMPLETE_TRANSCRIPT", "NON_ACTIVE_TRANSCRIPT"], [item["code"] for item in projected["diagnostics"]])
        self.assertEqual("9b00766d-15a7-52a8-b8db-1815edb755dd", projected["diagnostics"][0]["primary_id"])

    def test_same_id_different_bytes_is_collision(self) -> None:
        first = claim(0, IDS[10])
        changed = json.loads(json.dumps(first))
        changed["data"]["boundary"] = "changed"
        with self.assertRaisesRegex(TranscriptError, "collision") as caught:
            replay(transcript([record(first, 1), record(changed, 1)]))
        self.assertEqual("ID_COLLISION", caught.exception.code)

    def test_wrong_handoff_recipient_is_rejected(self) -> None:
        source = claim(0, IDS[10])
        offer = event(1, "handoff_offer", {
            "handoff_id": IDS[12], "claim_id": IDS[10], "generation": "0", "parent_claim_event_id": source["id"],
            "to_participant_instance_id": IDS[31], "boundary": "x", "boundary_digest": "sha-256:" + "3" * 64,
            "evidence_set_digest": "sha-256:" + "4" * 64, "next_action": "x", "unresolved_risks": [],
        }, correlation=source["id"], causation=source["id"])
        accept = event(2, "handoff_accept", {
            "handoff_id": IDS[12], "offer_event_id": offer["id"], "source_claim_event_id": source["id"],
            "claim_id": IDS[10], "generation": "0", "boundary_digest": "sha-256:" + "3" * 64,
            "evidence_set_digest": "sha-256:" + "4" * 64,
        }, correlation=source["id"], causation=offer["id"])
        with self.assertRaises(TranscriptError) as caught:
            replay(transcript([record(source, 1), record(offer, 2), record(accept, 3)]))
        self.assertEqual("INVALID_HANDOFF_PARTICIPANT", caught.exception.code)

    def test_jsonl_and_cli_emit_canonical_json(self) -> None:
        value = claim(0, IDS[10])
        document = transcript([record(value, 1)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transcript.jsonl"
            header = dict(document)
            records = header.pop("records")
            path.write_text(canonical_json({"transcript": header}) + "\n" + "\n".join(canonical_json(item) for item in records) + "\n", encoding="utf-8")
            self.assertEqual(document, load_transcript(path))
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("yukh_projection.py")), str(path), "--work-uri", WORK],
                check=True, capture_output=True, text=True,
            )
            output = completed.stdout
            self.assertEqual(canonical_json(parse_output(output)) + "\n", output)

    def test_transcript_id_vector(self) -> None:
        self.assertEqual(
            "9b00766d-15a7-52a8-b8db-1815edb755dd",
            transcript_id("tenant:example", CHANNEL, 0),
        )


def parse_output(value: str) -> dict:
    return json.loads(value)


if __name__ == "__main__":
    unittest.main()
