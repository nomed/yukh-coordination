#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { canonicalProjection, replay } from "../../js/lib/replay.mjs";
import { canonicalize } from "../../js/lib/canonical-json.mjs";
const source=JSON.parse(await readFile(process.argv[2],"utf8"));
try {
  const result=replay(source,process.argv[3]);
  process.stdout.write(`${process.argv[4] === "--wrapper" ? canonicalize(result) : canonicalProjection(result)}\n`);
} catch (error) {
  process.stderr.write(`${canonicalize({code:error.code ?? "INTERNAL_ERROR",message:error.message})}\n`);
  process.exitCode=1;
}
