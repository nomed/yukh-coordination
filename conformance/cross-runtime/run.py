#!/usr/bin/env python3
"""Run both independent CLIs and compare canonical projection bytes."""

from __future__ import annotations
import argparse, hashlib, json, subprocess, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[1]

def invoke(command):
 result=subprocess.run(command,cwd=ROOT,capture_output=True)
 if result.returncode:
  raise RuntimeError(f"{command[0]} failed ({result.returncode}): {result.stderr.decode()}")
 return result.stdout

def main():
 parser=argparse.ArgumentParser(); parser.add_argument("--update",action="store_true"); args=parser.parse_args()
 cases=json.loads((HERE/"cases/index.json").read_text()); results=[]; failures=[]
 for case in cases:
  path=ROOT/case["path"]; work=case["work_uri"]
  python_bytes=invoke([sys.executable,str(HERE/"python_adapter.py"),str(path),work])
  js_bytes=invoke(["node",str(HERE/"js_adapter.mjs"),str(path),work])
  if python_bytes != js_bytes:
   failures.append(f"{case['name']}: Python/JavaScript canonical projection mismatch")
   continue
  output=HERE/"expected"/f"{case['name']}.projection.canonical.json"; output.parent.mkdir(parents=True,exist_ok=True)
  if args.update: output.write_bytes(python_bytes)
  elif not output.exists() or output.read_bytes()!=python_bytes: failures.append(f"{case['name']}: committed projection differs")
  results.append({"name":case["name"],"projection":str(output.relative_to(ROOT)),"digest":"sha-256:"+hashlib.sha256(python_bytes).hexdigest(),"bytes":len(python_bytes)})
 expected_index=HERE/"expected/index.json"; encoded=(json.dumps(results,indent=2,sort_keys=True)+"\n").encode()
 if args.update: expected_index.write_bytes(encoded)
 elif not expected_index.exists() or expected_index.read_bytes()!=encoded: failures.append("expected/index.json differs")
 if failures:
  print("\n".join(failures),file=sys.stderr); return 1
 print(f"PASS: {len(results)} common transcripts are byte-identical across Python and JavaScript")
 return 0

if __name__=="__main__": raise SystemExit(main())
