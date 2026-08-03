#!/usr/bin/env bash
set -euo pipefail

grep -q '^  - Tutorial:' mkdocs.yml
grep -q '^  - How-to:' mkdocs.yml
grep -q '^  - Reference:' mkdocs.yml
grep -q '^  - Explanation:' mkdocs.yml
grep -q 'not production-ready' documentation/index.md
grep -q 'npm run replay' documentation/tutorials/first-replay.md

if grep -RiqE '(```|~~~)mermaid' documentation mkdocs.yml; then
  echo "Mermaid is not permitted in public documentation" >&2
  exit 1
fi
