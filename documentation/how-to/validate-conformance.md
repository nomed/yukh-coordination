# Validate the conformance corpus

Run the dependency-light protocol checks:

```sh
python3 conformance/generate.py
python3 conformance/validate.py --check-manifest
python3 conformance/signatures/verify.py
python3 conformance/cross-runtime/run.py
npm test
git diff --exit-code
```

`standards-schema.py` additionally requires the version pinned in
`conformance/standards-requirements.txt`.

A clean diff proves regeneration is byte-stable. Passing tests qualify the
checked-in contracts; they do not qualify a deployment.
