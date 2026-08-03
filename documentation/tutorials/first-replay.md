# Replay the first transcript

This tutorial derives work state locally. It uses no network or credentials.

## Requirements

- Git
- Node.js 24

## Run

```sh
git clone https://github.com/nomed/yukh-coordination.git
cd yukh-coordination
npm run replay -- \
  --input conformance/cross-runtime/cases/claim.json \
  --work https://example.test/issues/42 \
  --pretty
```

The result contains:

- `state: "claimed"`;
- the active claim under `contenders`;
- `completeness: "complete"`;
- `final: true` because every sequence and receipt boundary is present.

Replace `claim.json` with `sequence-gap.json`. The command exits non-zero and
marks the projection incomplete. It does not guess across missing history.
