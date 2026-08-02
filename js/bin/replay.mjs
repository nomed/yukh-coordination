#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { canonicalize, parseJson } from "../lib/canonical-json.mjs";
import { replay } from "../lib/replay.mjs";

const { values } = parseArgs({ options: { input: { type: "string", short: "i" }, work: { type: "string", short: "w" }, pretty: { type: "boolean", default: false } } });
if (!values.input || !values.work) {
  console.error("usage: replay --input TRANSCRIPT.json|jsonl --work ABSOLUTE_WORK_URI [--pretty]");
  process.exitCode = 2;
} else {
  try {
    const source = await readFile(values.input, "utf8");
    let input;
    if (values.input.endsWith(".jsonl")) {
      const lines = source.split(/\r?\n/u).filter((line) => line.trim());
      const entries = lines.map(parseJson);
      const header = entries.shift();
      if (!header || Object.keys(header).length !== 1 || !header.transcript) throw new Error("first JSONL object must contain only transcript");
      input = { ...header.transcript, records: entries };
    } else input = parseJson(source);
    const result = replay(input, values.work);
    process.stdout.write(`${values.pretty ? JSON.stringify(result, null, 2) : canonicalize(result)}\n`);
    if (!result.projection.final) process.exitCode = 1;
  } catch (error) {
    console.error(canonicalize({ code: error.code ?? "INVALID_TRANSCRIPT", message: error.message }));
    process.exitCode = 2;
  }
}
