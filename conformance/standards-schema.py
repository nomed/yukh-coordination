#!/usr/bin/env python3
"""Independent Draft 2020-12 validation using pinned python-jsonschema."""
import importlib.metadata, json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker, RefResolver

ROOT=Path(__file__).resolve().parents[1]; expected_version="4.10.3"; actual=importlib.metadata.version("jsonschema")
if actual != expected_version: raise SystemExit(f"jsonschema {expected_version} required, found {actual}")
store={}; schema_paths=list((ROOT/"schema").rglob("*.schema.json"))
for path in schema_paths:
 schema=json.loads(path.read_text()); Draft202012Validator.check_schema(schema); store[schema["$id"]]=schema
semantic_only={
 "conformance/fixtures/negative/root-correlation.json",
 "conformance/fixtures/negative/child-causation.json",
 "conformance/fixtures/negative/presence-expiry.json",
 "conformance/fixtures/negative/projection-high-water-mismatch.json",
}
failures=[]; fixtures=json.loads((ROOT/"conformance/fixtures/index.json").read_text())
for item in fixtures:
 path=ROOT/item["path"]; schema_path=ROOT/item["schema"]; schema=json.loads(schema_path.read_text())
 validator=Draft202012Validator(schema,resolver=RefResolver.from_schema(schema,store=store),format_checker=FormatChecker())
 valid=validator.is_valid(json.loads(path.read_text())); expected=item["valid"] or item["path"] in semantic_only
 if valid != expected: failures.append(f"{item['path']}: schema_valid={valid}, expected={expected}")
if failures: raise SystemExit("\n".join(failures))
print(f"PASS: standards jsonschema {actual}, {len(schema_paths)} metaschemas, {len(fixtures)} fixtures")
