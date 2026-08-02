from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from yukh_projection import (
    ReplayEngine,
    TranscriptError,
    canonical_bytes,
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
    return {"event": value, "receipt": receipt(value, sequence, instance=instance), "receipt_verified": True}


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
        "origin_sequence": 1,
        "high_water_sequence": high_water if high_water is not None else max(item["receipt"]["sequence"] for item in records),
        "high_water_receipt_verified": True,
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
    def test_forensic_reasons_are_sorted_and_make_projection_incomplete(self) -> None:
        value = claim(0, IDS[10])
        item = record(value, 2)
        item["receipt_verified"] = False
        document = transcript([item], high_water=1, lifecycle="redacted")
        document["origin_sequence"] = 2
        document["high_water_receipt_verified"] = False
        engine = ReplayEngine(document)
        projected = engine.run()[0]
        self.assertEqual(
            ["non-active-lifecycle", "record-after-high-water", "sequence-gap", "unverified-high-water", "unverified-receipt"],
            engine.conformance()["reasons"],
        )
        self.assertEqual("incomplete", projected["completeness"])
        self.assertFalse(projected["final"])

    def test_exact_duplicate_is_idempotent_and_reordering_is_neutral(self) -> None:
        first = claim(0, IDS[10])
        second = claim(1, IDS[11])
        ordered = transcript([record(first, 1), record(second, 2)])
        reordered = transcript([record(second, 2), record(first, 1), record(first, 1)])
        ordered_engine = ReplayEngine(ordered)
        reordered_engine = ReplayEngine(reordered)
        self.assertEqual(ordered_engine.run(), reordered_engine.run())
        self.assertEqual([], reordered_engine.conformance()["reasons"])

    def test_receipt_and_sequence_collisions_have_exact_admission_codes(self) -> None:
        first = claim(0, IDS[10])
        changed_receipt = record(first, 1)
        changed_receipt["receipt"]["cursor"] = "changed"
        with self.assertRaises(TranscriptError) as caught:
            replay(transcript([record(first, 1), changed_receipt]))
        self.assertEqual("receipt-mismatch", caught.exception.code)

        second = claim(1, IDS[11])
        with self.assertRaises(TranscriptError) as caught:
            replay(transcript([record(first, 1), record(second, 1)]))
        self.assertEqual("sequence-collision", caught.exception.code)

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
        with self.assertRaises(TranscriptError) as caught:
            replay(transcript([record(first, 1), record(changed, 1)]))
        self.assertEqual("event-id-collision", caught.exception.code)

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
        self.assertEqual("handoff-precondition-failed", caught.exception.code)

    def test_multiple_offers_project_and_competing_acceptance_fails(self) -> None:
        source = claim(0, IDS[10])
        offers = []
        for index, handoff_id, recipient in ((1, IDS[12], IDS[31]), (2, IDS[13], IDS[32])):
            offers.append(event(index, "handoff_offer", {
                "handoff_id": handoff_id, "claim_id": IDS[10], "generation": "0",
                "parent_claim_event_id": source["id"], "to_participant_instance_id": recipient,
                "boundary": "x", "boundary_digest": "sha-256:" + "3" * 64,
                "evidence_set_digest": "sha-256:" + "4" * 64, "next_action": "x", "unresolved_risks": [],
            }, correlation=source["id"], causation=source["id"]))
        offers[1]["data"]["parent_claim_event_id"] = offers[0]["id"]
        offers[1]["causation_id"] = offers[0]["id"]
        projected = replay(transcript([record(source, 1), record(offers[0], 2), record(offers[1], 3)]))[0]
        self.assertEqual("handoff_offered", projected["state"])
        self.assertEqual([IDS[12], IDS[13]], projected["handoff_offer_ids"])

        def acceptance(index: int, offer_value: dict, handoff_id: str) -> dict:
            return event(index, "handoff_accept", {
                "handoff_id": handoff_id, "offer_event_id": offer_value["id"],
                "source_claim_event_id": source["id"], "claim_id": IDS[10], "generation": "0",
                "boundary_digest": "sha-256:" + "3" * 64, "evidence_set_digest": "sha-256:" + "4" * 64,
            }, correlation=source["id"], causation=offer_value["id"])

        accepted = acceptance(3, offers[0], IDS[12])
        competing = acceptance(4, offers[1], IDS[13])
        with self.assertRaises(TranscriptError) as caught:
            replay(transcript([
                record(source, 1), record(offers[0], 2), record(offers[1], 3),
                record(accepted, 4, instance=IDS[31]), record(competing, 5, instance=IDS[32]),
            ]))
        self.assertEqual("handoff-precondition-failed", caught.exception.code)

    def test_invalid_handoff_offer_has_exact_admission_code(self) -> None:
        source = claim(0, IDS[10])
        invalid = event(1, "handoff_offer", {
            "handoff_id": IDS[12], "claim_id": IDS[10], "generation": "0",
            "parent_claim_event_id": IDS[19], "to_participant_instance_id": IDS[31],
            "boundary": "x", "boundary_digest": "sha-256:" + "3" * 64,
            "evidence_set_digest": "sha-256:" + "4" * 64, "next_action": "x", "unresolved_risks": [],
        }, correlation=source["id"], causation=source["id"])
        with self.assertRaises(TranscriptError) as caught:
            replay(transcript([record(source, 1), record(invalid, 2)]))
        self.assertEqual("invalid-handoff-offer", caught.exception.code)

    def test_evidence_binding_outcomes_and_failure_code(self) -> None:
        descriptor = {
            "uri": "https://example.test/evidence/1", "media_type": "application/json",
            "digest": {"algorithm": "sha-256", "value": "2" * 64}, "declared_size": "1",
        }
        root = event(0, "question", {"question": "verify?"}, correlation=IDS[0])
        root["evidence"] = [descriptor]
        descriptor_digest = "sha-256:" + hashlib.sha256(
            b"yukh.evidence-descriptor.v0.1\0" + canonical_bytes(descriptor)
        ).hexdigest()
        verification_data = {
            "referenced_event_id": root["id"], "descriptor_digest": descriptor_digest,
            "uri": descriptor["uri"], "algorithm": "sha-256", "expected_digest": "sha-256:" + "2" * 64,
            "observed_digest": "sha-256:" + "2" * 64, "outcome": "verified", "method": "fixture",
            "verified_at": "2026-08-02T16:00:00.000Z", "verifier_policy_version": "v1",
        }
        for outcome in ("verified", "mismatch", "unavailable", "unauthorized", "inconclusive"):
            data = json.loads(json.dumps(verification_data))
            data["outcome"] = outcome
            if outcome in {"unavailable", "unauthorized", "inconclusive"}:
                data.pop("observed_digest")
                data["reason"] = "fixture outcome"
            verification = event(1, "evidence_verification", data, correlation=root["id"], causation=root["id"])
            self.assertEqual("complete", replay(transcript([record(root, 1), record(verification, 2)]))[0]["completeness"])

        verification = event(1, "evidence_verification", verification_data, correlation=root["id"], causation=root["id"])
        invalid = json.loads(json.dumps(verification))
        invalid["data"]["expected_digest"] = "sha-256:" + "9" * 64
        invalid_record = record(invalid, 2)
        with self.assertRaises(TranscriptError) as caught:
            replay(transcript([record(root, 1), invalid_record]))
        self.assertEqual("evidence-binding-failed", caught.exception.code)

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
