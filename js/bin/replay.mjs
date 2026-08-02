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
      if (header?.kind !== "transcript") throw new Error("first JSONL record must be a transcript header");
      delete header.kind;
      input = { ...header, records: entries.map((entry) => entry.kind === "record" ? (delete entry.kind, entry) : entry) };
    } else input = parseJson(source);
    const result = replay(input, values.work);
    process.stdout.write(`${values.pretty ? JSON.stringify(result, null, 2) : canonicalize(result)}\n`);
    if (!result.projection.final) process.exitCode = 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
