#!/usr/bin/env python3
"""Accountable maintenance command for the explicit manifest input list."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; out=ROOT/"conformance"; target=out/"manifest-inputs.txt"
files={*(p for p in out.rglob("*") if p.is_file() and p.name not in {"SHA256SUMS","manifest-inputs.txt"} and "__pycache__" not in p.parts and p.suffix != ".pyc"), *ROOT.joinpath("schema").rglob("*.json"), *ROOT.joinpath("js").rglob("*.mjs"), ROOT/"package.json", ROOT/".gitignore", ROOT/".context/rfcs/RFC-0001-protocol-v0.1.md", ROOT/".context/rfcs/RFC-0002-mvp-security-boundary.md", target}
target.write_text("\n".join(sorted(str(path.relative_to(ROOT)) for path in files))+"\n")
print(f"updated explicit manifest allow-list: {len(files)} paths")
