#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalDigest, domainDigest } from "../../js/lib/replay.mjs";
import { canonicalize, parseJson } from "../../js/lib/canonical-json.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const index = parseJson(await readFile(resolve(repository, "conformance/canonical/index.json"), "utf8"));
const results = [];
for (const vector of index) {
  const input = parseJson(await readFile(resolve(repository, vector.input), "utf8"));
  const expectedBytes = await readFile(resolve(repository, vector.canonical), "utf8");
  const actualBytes = canonicalize(input);
  if (actualBytes !== expectedBytes) throw new Error(`${vector.name}: canonical bytes differ`);
  if (canonicalDigest(input) !== vector.digest) throw new Error(`${vector.name}: canonical digest differs`);
  if (vector.domain_prefix && domainDigest(vector.domain_prefix, input) !== vector.domain_digest) throw new Error(`${vector.name}: domain digest differs`);
  results.push({ name: vector.name, canonical_digest: vector.digest, ...(vector.domain_digest ? { domain_digest: vector.domain_digest } : {}) });
}
process.stdout.write(`${canonicalize({ specversion: "0.1", vectors: results })}\n`);
