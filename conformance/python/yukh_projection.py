"""Independent stdlib replay/projection engine for Yukh Coordination v0.1.

This module deliberately has no relay, network, authentication, JSON Schema, or
third-party runtime dependency.  It validates replay-time application
invariants over already admitted event/receipt records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


TRANSCRIPT_NAMESPACE = uuid.UUID("44a2ca56-05fd-5e2c-aba3-ef07363b75ae")
WORK_TYPES = {
    "claim", "progress", "question", "answer", "review_request", "verdict",
    "handoff_offer", "handoff_accept", "release", "evidence_verification",
}
ROOT_TYPES = {"claim", "question", "review_request"}
CHILD_TYPES = WORK_TYPES - ROOT_TYPES
LIFECYCLES = {"active", "redacted", "deleted"}
COMPLETENESS = {"complete", "incomplete"}


class TranscriptError(ValueError):
    """A stable validation failure for an invalid accepted transcript."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TranscriptError("DUPLICATE_JSON_KEY", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=lambda value: (_ for _ in ()).throw(
                TranscriptError("INVALID_NUMBER", f"floating JSON number: {value}")
            ),
            parse_constant=lambda value: (_ for _ in ()).throw(
                TranscriptError("INVALID_NUMBER", f"non-finite JSON number: {value}")
            ),
        )
    except TranscriptError:
        raise
    except json.JSONDecodeError as exc:
        raise TranscriptError("INVALID_JSON", str(exc)) from exc


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _check_string(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TranscriptError("INVALID_UNICODE", "unpaired surrogate") from exc


def canonical_json(value: Any) -> str:
    """RFC 8785 serialization for this protocol's integer/string subset."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > 9007199254740991:
            raise TranscriptError("INVALID_NUMBER", "integer outside interoperable range")
        return str(value)
    if isinstance(value, float):
        raise TranscriptError("INVALID_NUMBER", "floating numbers are unsupported")
    if isinstance(value, str):
        _check_string(value)
        return json.encoder.encode_basestring(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TranscriptError("INVALID_JSON", "object key is not a string")
            _check_string(key)
        parts = []
        for key in sorted(value, key=_utf16_key):
            parts.append(canonical_json(key) + ":" + canonical_json(value[key]))
        return "{" + ",".join(parts) + "}"
    raise TranscriptError("INVALID_JSON", f"unsupported JSON value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def event_digest(event: dict[str, Any]) -> str:
    return "sha-256:" + hashlib.sha256(canonical_bytes(event)).hexdigest()


def _reject_event_numbers(value: Any) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, (int, float)):
        raise TranscriptError("INVALID_NUMBER", "client event contains a JSON number")
    if isinstance(value, list):
        for item in value:
            _reject_event_numbers(item)
        return
    if isinstance(value, dict):
        for item in value.values():
            _reject_event_numbers(item)
        return
    raise TranscriptError("INVALID_JSON", "unsupported event value")


def transcript_id(tenant_id: str, channel_uri: str, epoch: int) -> str:
    name = f"{tenant_id}\0{channel_uri}\0{epoch}"
    return str(uuid.uuid5(TRANSCRIPT_NAMESPACE, name))


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise TranscriptError(code, message)


def _obj(value: Any, name: str) -> dict[str, Any]:
    _require(isinstance(value, dict), "INVALID_TRANSCRIPT", f"{name} must be an object")
    return value


def load_transcript(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        items = [parse_json(line) for line in text.splitlines() if line.strip()]
        _require(bool(items), "INVALID_TRANSCRIPT", "empty JSONL transcript")
        header = _obj(items[0], "JSONL header")
        _require(set(header) == {"transcript"}, "INVALID_TRANSCRIPT", "first JSONL object must contain only transcript")
        document = dict(_obj(header["transcript"], "transcript header"))
        document["records"] = items[1:]
        return document
    document = _obj(parse_json(text), "transcript")
    return document


@dataclass
class Claim:
    claim_id: str
    generation: str
    event_id: str
    work_uri: str
    active: bool = True
    last_lifecycle_event: str = ""
    offers: dict[str, "Offer"] = field(default_factory=dict)


@dataclass
class Offer:
    handoff_id: str
    event_id: str
    claim_key: tuple[str, str]
    recipient_instance: str
    boundary_digest: str
    evidence_set_digest: str
    accepted_event_id: str | None = None


class ReplayEngine:
    def __init__(self, transcript: dict[str, Any]):
        allowed = {
            "metadata", "transcript_epoch", "completeness", "lifecycle",
            "high_water_sequence", "records",
        }
        _require(set(transcript) <= allowed, "INVALID_TRANSCRIPT", "unknown transcript field")
        self.metadata = _obj(transcript.get("metadata"), "metadata")
        for name in ("tenant_id", "channel_id", "channel_uri"):
            _require(isinstance(self.metadata.get(name), str) and bool(self.metadata[name]), "INVALID_TRANSCRIPT", f"metadata.{name} required")
        self.tenant_id = self.metadata["tenant_id"]
        self.channel_id = self.metadata["channel_id"]
        self.channel_uri = self.metadata["channel_uri"]
        self.epoch = transcript.get("transcript_epoch")
        self.declared_completeness = transcript.get("completeness")
        self.lifecycle = transcript.get("lifecycle")
        self.high_water = transcript.get("high_water_sequence")
        self.records = transcript.get("records")
        _require(isinstance(self.epoch, int) and self.epoch >= 0, "INVALID_TRANSCRIPT", "invalid transcript_epoch")
        _require(self.declared_completeness in COMPLETENESS, "INVALID_TRANSCRIPT", "invalid completeness")
        _require(self.lifecycle in LIFECYCLES, "INVALID_TRANSCRIPT", "invalid lifecycle")
        _require(isinstance(self.high_water, int) and self.high_water >= 1, "INVALID_TRANSCRIPT", "invalid high_water_sequence")
        _require(isinstance(self.records, list), "INVALID_TRANSCRIPT", "records must be an array")
        self.events: dict[str, tuple[bytes, dict[str, Any], dict[str, Any]]] = {}
        self.sequence_records: dict[int, str] = {}
        self.claims: dict[tuple[str, str], Claim] = {}
        self.used_claims: set[tuple[str, str]] = set()
        self.offers_by_event: dict[str, Offer] = {}
        self.accepted_without_successor: dict[str, tuple[str, int]] = {}
        self.work_history: set[str] = set()
        self.conflict_trigger: dict[str, int] = {}
        self.derived_incomplete = self.declared_completeness == "incomplete"

    def run(self) -> list[dict[str, Any]]:
        normalized: list[tuple[int, bytes, dict[str, Any], dict[str, Any]]] = []
        for index, raw in enumerate(self.records):
            record = _obj(raw, f"records[{index}]")
            _require(set(record) == {"event", "receipt"}, "INVALID_TRANSCRIPT", "record requires only event and receipt")
            event = _obj(record["event"], "event")
            receipt = _obj(record["receipt"], "receipt")
            sequence = receipt.get("sequence")
            _require(isinstance(sequence, int) and sequence >= 1, "INVALID_RECEIPT", "invalid sequence")
            normalized.append((sequence, canonical_bytes(event), event, receipt))
        normalized.sort(key=lambda item: (item[0], item[1]))

        for sequence, event_bytes, event, receipt in normalized:
            event_id = event.get("id")
            _require(isinstance(event_id, str), "INVALID_ENVELOPE", "event id required")
            if event_id in self.events:
                original_bytes, _, original_receipt = self.events[event_id]
                if event_bytes != original_bytes:
                    raise TranscriptError("ID_COLLISION", f"event id collision: {event_id}")
                _require(canonical_bytes(receipt) == canonical_bytes(original_receipt), "INVALID_RECEIPT", "duplicate event has different receipt")
                continue
            if sequence in self.sequence_records:
                raise TranscriptError("INVALID_RECEIPT", f"sequence reused by {event_id}")
            self._validate_binding(event, receipt)
            self.events[event_id] = (event_bytes, event, receipt)
            self.sequence_records[sequence] = event_id
            self._apply(event, receipt)

        expected = set(range(1, self.high_water + 1))
        if set(self.sequence_records) != expected:
            self.derived_incomplete = True
        if self.sequence_records and max(self.sequence_records) > self.high_water:
            raise TranscriptError("INVALID_TRANSCRIPT", "sequence exceeds high water")
        works = sorted(self.work_history)
        return [self._project(work) for work in works]

    def _validate_binding(self, event: dict[str, Any], receipt: dict[str, Any]) -> None:
        required_event = {"specversion", "id", "type", "channel", "source", "participant", "time", "data", "evidence", "extensions"}
        _require(required_event <= set(event), "INVALID_ENVELOPE", "missing event field")
        _reject_event_numbers(event)
        _require(len(canonical_bytes(event)) <= 65536, "RESOURCE_LIMIT", "event byte limit")
        _require(event["specversion"] == "0.1", "UNSUPPORTED_VERSION", "unsupported event version")
        _require(event["channel"] == self.channel_uri, "CROSS_CHANNEL_REFERENCE", "event channel mismatch")
        _require(event["type"] in (WORK_TYPES | {"join", "presence", "leave"}), "INVALID_EVENT_TYPE", "unknown type")
        _require(receipt.get("event_id") == event["id"], "INVALID_RECEIPT", "receipt event mismatch")
        _require(receipt.get("tenant_id") == self.tenant_id, "CROSS_CHANNEL_REFERENCE", "tenant mismatch")
        _require(receipt.get("channel_id") == self.channel_id and receipt.get("channel_uri") == self.channel_uri, "CROSS_CHANNEL_REFERENCE", "receipt channel mismatch")
        _require(receipt.get("transcript_epoch") == self.epoch, "INVALID_RECEIPT", "transcript epoch mismatch")
        participant = _obj(event["participant"], "participant")
        _require(receipt.get("participant_id") == participant.get("id"), "INVALID_RECEIPT", "participant label mismatch")
        _require(receipt.get("event_digest") == event_digest(event), "EVENT_DIGEST_MISMATCH", "event digest mismatch")
        _require(receipt.get("append_outcome") == "appended", "INVALID_RECEIPT", "invalid append outcome")
        _require(receipt.get("signature_algorithm") == "ed25519", "INVALID_RECEIPT", "invalid signature algorithm")
        _require(isinstance(receipt.get("participant_instance_id"), str), "INVALID_RECEIPT", "participant instance required")
        if event["type"] in WORK_TYPES:
            _require(isinstance(event.get("work"), dict) and isinstance(event["work"].get("uri"), str), "INVALID_ENVELOPE", "work URI required")
            _require(isinstance(event.get("correlation_id"), str), "INVALID_ENVELOPE", "correlation required")
        if event["type"] in CHILD_TYPES:
            causation = event.get("causation_id")
            _require(isinstance(causation, str), "INVALID_ENVELOPE", "causation required")
            _require(causation in self.events, "UNRESOLVED_CAUSATION", f"missing causation: {causation}")
            _, parent, _ = self.events[causation]
            _require(parent.get("channel") == event["channel"] and parent.get("work") == event.get("work"), "CROSS_CHANNEL_REFERENCE", "causal scope mismatch")
            _require(parent.get("correlation_id") == event.get("correlation_id"), "INVALID_REFERENCE", "correlation mismatch")
        if event["type"] in ROOT_TYPES:
            _require(event["correlation_id"] == event["id"], "INVALID_REFERENCE", "root correlation mismatch")

    def _claim_for(self, data: dict[str, Any], work: str) -> Claim:
        key = (data.get("claim_id"), data.get("generation"))
        claim = self.claims.get(key)
        _require(claim is not None and claim.work_uri == work, "INVALID_CLAIM_TRANSITION", "unknown claim generation")
        return claim

    def _apply(self, event: dict[str, Any], receipt: dict[str, Any]) -> None:
        kind = event["type"]
        if kind not in WORK_TYPES:
            return
        work = event["work"]["uri"]
        self.work_history.add(work)
        data = _obj(event["data"], "data")
        event_id = event["id"]
        sequence = receipt["sequence"]

        if kind == "claim":
            key = (data.get("claim_id"), data.get("generation"))
            _require(all(isinstance(item, str) for item in key), "INVALID_PAYLOAD", "claim identity required")
            _require(key not in self.used_claims, "INVALID_CLAIM_TRANSITION", "claim generation reused")
            predecessor = data.get("predecessor_handoff_event")
            if predecessor is not None:
                _require(predecessor in self.accepted_without_successor, "INVALID_CLAIM_TRANSITION", "invalid predecessor handoff")
                _require(event.get("causation_id") == predecessor, "INVALID_REFERENCE", "successor causation mismatch")
                del self.accepted_without_successor[predecessor]
            _require(len(self._active(work)) < 32, "RESOURCE_LIMIT", "active claim limit")
            claim = Claim(key[0], key[1], event_id, work, last_lifecycle_event=event_id)
            self.claims[key] = claim
            self.used_claims.add(key)
            self._update_conflict_trigger(work, sequence)
            return

        if kind in {"progress", "release", "handoff_offer"}:
            claim = self._claim_for(data, work)
            _require(claim.active, "INVALID_CLAIM_TRANSITION", "claim is not active")
            parent = data.get("parent_claim_event_id")
            _require(parent == claim.last_lifecycle_event and event.get("causation_id") == parent, "INVALID_REFERENCE", "claim lifecycle parent mismatch")
            if kind == "progress":
                claim.last_lifecycle_event = event_id
            elif kind == "release":
                claim.active = False
                claim.last_lifecycle_event = event_id
                claim.offers.clear()
                self._update_conflict_trigger(work, sequence)
            else:
                _require(len(claim.offers) < 32, "RESOURCE_LIMIT", "active handoff offer limit")
                offer = Offer(
                    data.get("handoff_id"), event_id, (claim.claim_id, claim.generation),
                    data.get("to_participant_instance_id"), data.get("boundary_digest"),
                    data.get("evidence_set_digest"),
                )
                _require(all(isinstance(value, str) for value in (offer.handoff_id, offer.recipient_instance, offer.boundary_digest, offer.evidence_set_digest)), "INVALID_PAYLOAD", "invalid handoff offer")
                claim.offers[event_id] = offer
                self.offers_by_event[event_id] = offer
                claim.last_lifecycle_event = event_id
            return

        if kind == "handoff_accept":
            offer_id = data.get("offer_event_id")
            offer = self.offers_by_event.get(offer_id)
            _require(offer is not None, "INVALID_REFERENCE", "unknown handoff offer")
            claim = self.claims[offer.claim_key]
            _require(claim.active and offer.accepted_event_id is None, "HANDOFF_PRECONDITION_FAILED", "handoff is not current")
            _require(offer_id in claim.offers, "HANDOFF_PRECONDITION_FAILED", "offer was closed")
            _require(event.get("causation_id") == offer_id, "INVALID_REFERENCE", "handoff causation mismatch")
            _require(receipt["participant_instance_id"] == offer.recipient_instance, "INVALID_HANDOFF_PARTICIPANT", "wrong handoff recipient")
            _require(data.get("handoff_id") == offer.handoff_id and data.get("claim_id") == claim.claim_id and data.get("generation") == claim.generation, "HANDOFF_PRECONDITION_FAILED", "handoff identity changed")
            _require(data.get("boundary_digest") == offer.boundary_digest and data.get("evidence_set_digest") == offer.evidence_set_digest, "HANDOFF_PRECONDITION_FAILED", "handoff boundary changed")
            offer.accepted_event_id = event_id
            claim.offers.clear()
            claim.last_lifecycle_event = event_id
            self.accepted_without_successor[event_id] = (claim.claim_id, sequence)
            return

        parent_fields = {
            "answer": ("question_event_id", "question"),
            "verdict": ("review_event_id", "review_request"),
            "evidence_verification": ("referenced_event_id", None),
        }
        if kind in parent_fields:
            field_name, expected_type = parent_fields[kind]
            parent_id = data.get(field_name)
            _require(parent_id == event.get("causation_id"), "INVALID_REFERENCE", f"{field_name} must equal causation")
            _require(parent_id in self.events, "INVALID_REFERENCE", "referenced event missing")
            _, parent, _ = self.events[parent_id]
            if expected_type is not None:
                _require(parent["type"] == expected_type, "INVALID_REFERENCE", "referenced event has wrong type")
        if kind == "evidence_verification":
            self._validate_evidence_verification(data, parent)

        # Conversation, review, and evidence signals do not modify the closed
        # work-ownership projection.

    def _validate_evidence_verification(self, data: dict[str, Any], parent: dict[str, Any]) -> None:
        outcome = data.get("outcome")
        _require(outcome in {"verified", "mismatch", "unavailable", "unauthorized", "inconclusive"}, "INVALID_PAYLOAD", "invalid evidence outcome")
        if outcome in {"verified", "mismatch"}:
            _require(isinstance(data.get("observed_digest"), str) and "reason" not in data, "INVALID_PAYLOAD", "observed digest required")
        else:
            _require(isinstance(data.get("reason"), str) and "observed_digest" not in data, "INVALID_PAYLOAD", "reason required")
        matches = []
        for descriptor in parent.get("evidence", []):
            digest = "sha-256:" + hashlib.sha256(
                b"yukh.evidence-descriptor.v0.1\0" + canonical_bytes(descriptor)
            ).hexdigest()
            if digest == data.get("descriptor_digest"):
                matches.append(descriptor)
        _require(len(matches) == 1, "INVALID_REFERENCE", "evidence descriptor binding is missing or ambiguous")
        descriptor = matches[0]
        expected = "sha-256:" + descriptor.get("digest", {}).get("value", "")
        _require(
            data.get("uri") == descriptor.get("uri")
            and data.get("algorithm") == descriptor.get("digest", {}).get("algorithm")
            and data.get("expected_digest") == expected,
            "INVALID_PAYLOAD", "evidence descriptor fields differ",
        )

    def _active(self, work: str) -> list[Claim]:
        return [claim for claim in self.claims.values() if claim.work_uri == work and claim.active]

    def _update_conflict_trigger(self, work: str, sequence: int) -> None:
        count = len(self._active(work))
        if count > 1 and work not in self.conflict_trigger:
            self.conflict_trigger[work] = sequence
        elif count <= 1:
            self.conflict_trigger.pop(work, None)

    def _project(self, work: str) -> dict[str, Any]:
        active = self._active(work)
        contenders = sorted(claim.claim_id for claim in active)
        offers: list[str] = []
        diagnostics: list[dict[str, Any]] = []
        if len(active) > 1:
            state = "conflicting"
            event_ids = sorted(claim.event_id for claim in active)
            diagnostics.append({
                "sequence": self.conflict_trigger[work],
                "code": "CLAIM_CONFLICT",
                "severity": "warning",
                "primary_id": event_ids[0],
                "contender_ids": contenders,
                "contender_event_ids": event_ids,
            })
        elif len(active) == 1:
            offers = sorted(offer.handoff_id for offer in active[0].offers.values())
            state = "handoff_offered" if offers else "claimed"
        else:
            state = "released" if any(claim.work_uri == work for claim in self.claims.values()) else "unclaimed"

        for acceptance_id, (claim_id, sequence) in self.accepted_without_successor.items():
            _, acceptance, _ = self.events[acceptance_id]
            if acceptance["work"]["uri"] == work:
                diagnostics.append({
                    "sequence": sequence,
                    "code": "HANDOFF_ACCEPTED_UNCLAIMED",
                    "severity": "warning",
                    "primary_id": acceptance_id,
                    "event_id": acceptance_id,
                    "claim_id": claim_id,
                })

        completeness = "incomplete" if self.derived_incomplete else "complete"
        tid = transcript_id(self.tenant_id, self.channel_uri, self.epoch)
        if completeness == "incomplete":
            diagnostics.append({"sequence": self.high_water, "code": "INCOMPLETE_TRANSCRIPT", "severity": "error", "primary_id": tid})
        if self.lifecycle != "active":
            diagnostics.append({"sequence": self.high_water, "code": "NON_ACTIVE_TRANSCRIPT", "severity": "error", "primary_id": tid})
        diagnostics.sort(key=lambda item: (item["sequence"], item["code"], item["primary_id"]))
        return {
            "specversion": "0.1",
            "channel_id": self.channel_id,
            "work_uri": work,
            "state": state,
            "contenders": contenders,
            "handoff_offer_ids": offers,
            "diagnostics": diagnostics,
            "diagnostics_high_water_sequence": self.high_water,
            "as_of_sequence": self.high_water,
            "completeness": completeness,
            "lifecycle": self.lifecycle,
            "final": completeness == "complete" and self.lifecycle == "active",
        }


def replay(document: dict[str, Any]) -> list[dict[str, Any]]:
    return ReplayEngine(document).run()


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay Yukh Coordination v0.1 transcript")
    parser.add_argument("transcript", type=Path, help="JSON wrapper or JSONL transcript")
    parser.add_argument("--work-uri", help="emit one projection rather than the projection collection")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        projections = replay(load_transcript(args.transcript))
        if args.work_uri:
            matches = [item for item in projections if item["work_uri"] == args.work_uri]
            _require(len(matches) == 1, "WORK_NOT_FOUND", "requested work URI not found")
            output: Any = matches[0]
        else:
            output = {"specversion": "0.1", "projections": projections}
        sys.stdout.buffer.write(canonical_bytes(output) + b"\n")
        return 0
    except (OSError, TranscriptError) as exc:
        code = exc.code if isinstance(exc, TranscriptError) else "IO_ERROR"
        sys.stderr.write(canonical_json({"code": code, "message": str(exc)}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
