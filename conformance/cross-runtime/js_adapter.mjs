#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { canonicalProjection, replay } from "../../js/lib/replay.mjs";
const source=JSON.parse(await readFile(process.argv[2],"utf8"));
const result=replay(source,process.argv[3]);
process.stdout.write(`${canonicalProjection(result)}\n`);
