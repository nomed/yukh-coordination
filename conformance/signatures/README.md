# Signature vectors

The vectors reuse RFC 8032 test vector 1's seed and public key, then sign each
protocol's exact domain prefix plus its committed JCS preimage. They cover the
event receipt, RFC-0011 audit checkpoint and recovery-manifest boundaries. Test
keys are public fixtures and must never be used operationally.

Verification uses only Python's standard library and the local OpenSSL 3.x CLI:

```bash
python3 conformance/signatures/verify.py
```

The gate reconstructs PKCS#8/SPKI DER, proves the seed derives the recorded
public key, checks preimage length/digest, and verifies the fixed signature.
