#!/usr/bin/env python3
"""Dependency-light validator and canonicalizer for protocol v0.1 fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema"
UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class Invalid(ValueError):
    pass


def load_json(path: Path):
    def pairs(items):
        out={}
        for key,value in items:
            if key in out: raise Invalid(f"duplicate key: {key}")
            out[key]=value
        return out
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(Invalid(x)))


def pointer(document, fragment: str):
    value = document
    if fragment in ("", "#"):
        return value
    for token in fragment.removeprefix("#/").split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


def resolve(ref: str, base: Path):
    name, _, fragment = ref.partition("#")
    path = (base.parent / name).resolve() if name else base
    return pointer(load_json(path), "#" + fragment), path


def is_type(value, expected):
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
    }.get(expected, True)


def check(schema, value, base: Path, at="$", errors=None):
    errors = [] if errors is None else errors
    if "$ref" in schema:
        target, target_path = resolve(schema["$ref"], base)
        return check(target, value, target_path, at, errors)
    if "type" in schema and not is_type(value, schema["type"]):
        errors.append(f"{at}: expected {schema['type']}")
        return errors
    if "const" in schema and value != schema["const"]:
        errors.append(f"{at}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{at}: outside enum")
    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{at}: missing {key}")
        props = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in props:
                check(props[key], item, base, f"{at}.{key}", errors)
            elif additional is False:
                errors.append(f"{at}: unexpected {key}")
            elif isinstance(additional, dict):
                check(additional, item, base, f"{at}.{key}", errors)
        if len(value) > schema.get("maxProperties", sys.maxsize):
            errors.append(f"{at}: too many properties")
        if "propertyNames" in schema:
            for key in value:
                check(schema["propertyNames"], key, base, f"{at}.<key>", errors)
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", sys.maxsize):
            errors.append(f"{at}: item count")
        if schema.get("uniqueItems") and len({jcs(x) for x in value}) != len(value):
            errors.append(f"{at}: duplicate items")
        if "items" in schema:
            for i, item in enumerate(value):
                check(schema["items"], item, base, f"{at}[{i}]", errors)
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", sys.maxsize):
            errors.append(f"{at}: string length")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{at}: pattern")
        if schema.get("format") == "uri" and not urlparse(value).scheme:
            errors.append(f"{at}: absolute URI required")
        if schema.get("format") == "date-time":
            try: datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError: errors.append(f"{at}: invalid date-time")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            errors.append(f"{at}: numeric range")
    for branch in schema.get("allOf", []):
        check(branch, value, base, at, errors)
    if "anyOf" in schema and not any(not check(s, value, base, at, []) for s in schema["anyOf"]):
        errors.append(f"{at}: no anyOf branch")
    if "not" in schema and not check(schema["not"], value, base, at, []):
        errors.append(f"{at}: prohibited shape")
    if "if" in schema:
        branch = schema.get("then") if not check(schema["if"], value, base, at, []) else schema.get("else")
        if branch:
            check(branch, value, base, at, errors)
    return errors


def _key(value: str):
    return value.encode("utf-16-be", "surrogatepass")


def jcs(value) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9007199254740991:
            raise Invalid("integer outside interoperable range")
        return str(value).encode()
    if isinstance(value, float):
        raise Invalid("floating point unsupported")
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise Invalid("unpaired surrogate")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(x) for x in value) + b"]"
    if isinstance(value, dict):
        parts = (jcs(k) + b":" + jcs(value[k]) for k in sorted(value, key=_key))
        return b"{" + b",".join(parts) + b"}"
    raise Invalid(f"unsupported value {type(value)}")


def no_numbers(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        raise Invalid("client event contains JSON number")
    if isinstance(value, dict):
        for child in value.values(): no_numbers(child)
    if isinstance(value, list):
        for child in value: no_numbers(child)


def semantic_event(event):
    raw = jcs(event)
    if len(raw) > 65536: raise Invalid("event exceeds 64 KiB")
    no_numbers(event)
    typ, data = event["type"], event["data"]
    if typ in {"claim", "question", "review_request"} and event["correlation_id"] != event["id"]:
        raise Invalid("root correlation mismatch")
    parent = {"progress":"parent_claim_event_id", "answer":"question_event_id", "verdict":"review_event_id", "handoff_offer":"parent_claim_event_id", "handoff_accept":"offer_event_id", "release":"parent_claim_event_id", "evidence_verification":"referenced_event_id"}.get(typ)
    if parent and event["causation_id"] != data[parent]: raise Invalid("causation mismatch")
    if typ == "presence" and not data["valid_until"] > data["observed_at"]: raise Invalid("presence interval")
    if typ == "claim" and data["expected_active_claims"] != sorted(data["expected_active_claims"]): raise Invalid("claim observations unsorted")


def semantic_projection(value):
    if value["diagnostics_high_water_sequence"] != value["as_of_sequence"]: raise Invalid("projection high-water mismatch")
    if value["contenders"] != sorted(value["contenders"]): raise Invalid("contenders unsorted")
    if value["handoff_offer_ids"] != sorted(value["handoff_offer_ids"]): raise Invalid("handoff offers unsorted")
    diagnostics=value["diagnostics"]
    if len({d["code"] for d in diagnostics}) != len(diagnostics): raise Invalid("duplicate diagnostic code")
    if diagnostics != sorted(diagnostics,key=lambda d:(d["sequence"],d["code"],d["primary_id"])): raise Invalid("diagnostics unsorted")
    for d in diagnostics:
        if d["code"] == "CLAIM_CONFLICT":
            if d["contender_ids"] != sorted(d["contender_ids"]) or d["contender_event_ids"] != sorted(d["contender_event_ids"]): raise Invalid("conflict arrays unsorted")
            if d["primary_id"] != min(d["contender_event_ids"]): raise Invalid("conflict primary")
        if d["code"] == "HANDOFF_ACCEPTED_UNCLAIMED" and d["primary_id"] != d["event_id"]: raise Invalid("handoff primary")


def validate_file(path: Path, schema_path: Path):
    value = load_json(path); errors = check(load_json(schema_path), value, schema_path)
    if errors: raise Invalid("; ".join(errors))
    if schema_path.name == "envelope-0.1.schema.json": semantic_event(value)
    if schema_path.name == "projection-0.1.schema.json": semantic_projection(value)
    if schema_path.name in {"receipt-0.1.schema.json", "problem-0.1.schema.json"} and len(jcs(value)) > 16384: raise Invalid("document exceeds 16 KiB")
    return value


def check_refs(schema, base: Path):
    if isinstance(schema, dict):
        if "$ref" in schema:
            target, target_path = resolve(schema["$ref"], base)
            check_refs(target, target_path)
        for key, value in schema.items():
            if key != "$ref": check_refs(value, base)
    elif isinstance(schema, list):
        for value in schema: check_refs(value, base)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--check-manifest", action="store_true"); args = ap.parse_args()
    for schema_path in sorted(SCHEMA.rglob("*.schema.json")):
        check_refs(load_json(schema_path), schema_path)
    index = load_json(ROOT / "conformance/fixtures/index.json")
    failures=[]
    for item in index:
        path=ROOT/item["path"]; schema=ROOT/item["schema"]
        try: validate_file(path,schema); valid=True
        except (Invalid, KeyError, json.JSONDecodeError) as exc: valid=False; message=str(exc)
        if valid != item["valid"]: failures.append(f"{item['path']}: expected valid={item['valid']} ({message if not valid else 'accepted'})")
    vectors=load_json(ROOT/"conformance/canonical/index.json")
    for item in vectors:
        actual=jcs(load_json(ROOT/item["input"])); expected=(ROOT/item["canonical"]).read_bytes()
        if actual != expected: failures.append(f"{item['input']}: canonical mismatch")
        if "digest" in item and "sha-256:"+hashlib.sha256(actual).hexdigest()!=item["digest"]: failures.append(f"{item['input']}: digest mismatch")
        if "domain_prefix" in item and "sha-256:"+hashlib.sha256(item["domain_prefix"].encode()+actual).hexdigest()!=item["domain_digest"]: failures.append(f"{item['input']}: domain digest mismatch")
    if args.check_manifest:
        for line in (ROOT/"conformance/SHA256SUMS").read_text().splitlines():
            digest, name=line.split("  ",1); actual=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            if digest!=actual: failures.append(f"{name}: manifest mismatch")
    if failures:
        print("\n".join(failures),file=sys.stderr); return 1
    print(f"PASS: {len(index)} fixtures, {len(vectors)} canonical vectors")
    return 0


if __name__ == "__main__": raise SystemExit(main())
