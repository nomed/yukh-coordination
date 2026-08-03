#!/usr/bin/env python3
"""Verify the fixed Ed25519 protocol vectors with local OpenSSL 3.x."""
import hashlib, json, shutil, subprocess, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
openssl=shutil.which("openssl")
if not openssl: raise SystemExit("OpenSSL CLI is required")
vectors=sorted(Path(__file__).parent.glob("*-ed25519-rfc8032.json"))
for vector_path in vectors:
 vector=json.loads(vector_path.read_text()); seed=bytes.fromhex(vector["seed_hex"]); public=bytes.fromhex(vector["public_key_hex"]); signature=bytes.fromhex(vector["signature_hex"])
 message=vector["domain_prefix"].encode()+ (ROOT/vector["preimage"]).read_bytes()
 assert len(message)==vector["preimage_bytes"]
 assert "sha-256:"+hashlib.sha256(message).hexdigest()==vector["preimage_digest"]
 with tempfile.TemporaryDirectory() as directory:
  path=Path(directory); private_der=bytes.fromhex("302e020100300506032b657004220420")+seed; public_der=bytes.fromhex("302a300506032b6570032100")+public
  (path/"private.der").write_bytes(private_der); (path/"public.der").write_bytes(public_der); (path/"message.bin").write_bytes(message); (path/"signature.bin").write_bytes(signature)
  derived=subprocess.run([openssl,"pkey","-in",str(path/"private.der"),"-inform","DER","-pubout","-outform","DER"],capture_output=True,check=True).stdout
  assert derived==public_der, "seed/public key mismatch"
  subprocess.run([openssl,"pkeyutl","-verify","-rawin","-pubin","-inkey",str(path/"public.der"),"-keyform","DER","-in",str(path/"message.bin"),"-sigfile",str(path/"signature.bin")],capture_output=True,check=True)
print(f"PASS: {len(vectors)} fixed RFC8032-derived Ed25519 signatures")
