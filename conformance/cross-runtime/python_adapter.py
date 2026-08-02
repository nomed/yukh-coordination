#!/usr/bin/env python3
"""Adapt a common transcript to the independent Python projection CLI."""
import json, subprocess, sys, tempfile
from pathlib import Path

source=json.loads(Path(sys.argv[1]).read_text())
document={"metadata":source["metadata"],"transcript_epoch":source["transcript_epoch"],"completeness":source["declared_completeness"],"origin_sequence":source["origin_sequence"],"lifecycle":source["lifecycle"],"high_water_sequence":source["high_water_sequence"],"high_water_receipt_verified":source["high_water_receipt_verified"],"records":[{"event":r["event"],"receipt":r["receipt"],"receipt_verified":r["receipt_verified"]} for r in source["records"]]}
with tempfile.TemporaryDirectory() as directory:
 path=Path(directory)/"python.json"; path.write_text(json.dumps(document,separators=(",",":"),ensure_ascii=False))
 command=[sys.executable,str(Path(__file__).parents[1]/"python/yukh_projection.py"),str(path),"--work-uri",sys.argv[2]]
 result=subprocess.run(command,capture_output=True)
 sys.stdout.buffer.write(result.stdout); sys.stderr.buffer.write(result.stderr); raise SystemExit(result.returncode)
