#!/usr/bin/env python3
"""Run both independent CLIs and compare canonical projection bytes."""

from __future__ import annotations
import argparse, hashlib, json, subprocess, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[1]

def invoke(command): return subprocess.run(command,cwd=ROOT,capture_output=True)
def canonical(value): return (json.dumps(value,ensure_ascii=False,separators=(",",":"),sort_keys=True)+"\n").encode()

def main():
 parser=argparse.ArgumentParser(); parser.add_argument("--update",action="store_true"); args=parser.parse_args()
 canonical_vectors=json.loads((ROOT/"conformance/canonical/index.json").read_text()); failures=[]
 for vector in canonical_vectors:
  source=ROOT/vector["input"]; expected=(ROOT/vector["canonical"]).read_bytes()
  py=invoke([sys.executable,str(HERE/"canonical_python.py"),str(source)]); js=invoke(["node",str(HERE/"canonical_js.mjs"),str(source)])
  if py.returncode or js.returncode or py.stdout!=js.stdout or py.stdout!=expected: failures.append(f"canonical/{vector['name']}: runtime bytes differ")
  if "sha-256:"+hashlib.sha256(expected).hexdigest()!=vector["digest"]: failures.append(f"canonical/{vector['name']}: digest differs")
  if "domain_prefix" in vector and "sha-256:"+hashlib.sha256(vector["domain_prefix"].encode()+expected).hexdigest()!=vector["domain_digest"]: failures.append(f"canonical/{vector['name']}: domain digest differs")
 cases=json.loads((HERE/"cases/index.json").read_text()); results=[]
 for case in cases:
  path=ROOT/case["path"]; work=case["work_uri"]
  py=invoke([sys.executable,str(HERE/"python_adapter.py"),str(path),work]); js=invoke(["node",str(HERE/"js_adapter.mjs"),str(path),work,"--wrapper"])
  if case["mode"]=="projection-equal":
   if py.returncode: failures.append(f"{case['name']}: Python failed: {py.stderr.decode()}"); continue
   if js.returncode: failures.append(f"{case['name']}: JavaScript failed: {js.stderr.decode()}"); continue
   js_projection=canonical(json.loads(js.stdout)["projection"])
   if py.stdout != js_projection: failures.append(f"{case['name']}: Python/JavaScript canonical projection mismatch"); continue
   output=HERE/"expected"/f"{case['name']}.projection.canonical.json"; payload=py.stdout
   summary={"kind":"projection-equal","final":json.loads(payload)["final"]}
  else:
   if py.returncode:
    try: py_summary={"kind":"error","code":json.loads(py.stderr)["code"]}
    except Exception: failures.append(f"{case['name']}: unreadable Python error"); continue
   else: py_summary={"kind":"projection","final":json.loads(py.stdout)["final"],"reasons":[]}
   if js.returncode:
    try: js_summary={"kind":"error","code":json.loads(js.stderr)["code"]}
    except Exception: failures.append(f"{case['name']}: unreadable JavaScript error"); continue
   else:
    wrapper=json.loads(js.stdout); js_summary={"kind":"projection","final":wrapper["projection"]["final"],"reasons":wrapper["conformance"]["reasons"]}
   summary={"python":py_summary,"javascript":js_summary}
   if summary!=case["expected"]: failures.append(f"{case['name']}: outcome mismatch expected={case['expected']} actual={summary}"); continue
   output=HERE/"expected"/f"{case['name']}.outcome.canonical.json"; payload=canonical(summary)
  output.parent.mkdir(parents=True,exist_ok=True)
  if args.update: output.write_bytes(payload)
  elif not output.exists() or output.read_bytes()!=payload: failures.append(f"{case['name']}: committed output differs")
  results.append({"name":case["name"],"mode":case["mode"],"output":str(output.relative_to(ROOT)),"digest":"sha-256:"+hashlib.sha256(payload).hexdigest(),"bytes":len(payload)})
 expected_index=HERE/"expected/index.json"; encoded=(json.dumps(results,indent=2,sort_keys=True)+"\n").encode()
 if args.update: expected_index.write_bytes(encoded)
 elif not expected_index.exists() or expected_index.read_bytes()!=encoded: failures.append("expected/index.json differs")
 if failures:
  print("\n".join(failures),file=sys.stderr); return 1
 equal=sum(item["mode"]=="projection-equal" for item in results)
 print(f"PASS: {len(canonical_vectors)} canonical vectors; {equal} byte-identical projections; {len(results)-equal} explicit cross-runtime outcome specifications")
 return 0

if __name__=="__main__": raise SystemExit(main())
