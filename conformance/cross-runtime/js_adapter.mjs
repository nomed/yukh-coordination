#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { canonicalProjection, replay } from "../../js/lib/replay.mjs";
import { canonicalize } from "../../js/lib/canonical-json.mjs";
const source=JSON.parse(await readFile(process.argv[2],"utf8"));
const input={...source.metadata,transcript_epoch:source.transcript_epoch,origin_sequence:source.origin_sequence,high_water_sequence:source.high_water_sequence,high_water_receipt_verified:source.high_water_receipt_verified,lifecycle:source.lifecycle,records:source.records};
const result=replay(input,process.argv[3]);
process.stdout.write(`${process.argv[4] === "--wrapper" ? canonicalize(result) : canonicalProjection(result)}\n`);
