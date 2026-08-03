import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const canonical = (await readFile(resolve(root, "js/lib/canonical-json.mjs"), "utf8"))
  .replaceAll("export function ", "function ");
const client = (await readFile(resolve(root, "js/lib/primitives-client.mjs"), "utf8"))
  .replace('import { canonicalize, parseJson } from "./canonical-json.mjs";\n\n', "");
const bundle = `// Generated deterministically by .github/scripts/build-primitives-client.mjs.\n${canonical}\n${client}`;
const checksum = `${createHash("sha256").update(bundle).digest("hex")}  primitives-client.mjs\n`;
const output = resolve(root, "js/dist/primitives-client.mjs");
const sums = resolve(root, "js/dist/SHA256SUMS");

if (process.argv.includes("--check")) {
  const observedBundle = await readFile(output, "utf8");
  const observedSums = await readFile(sums, "utf8");
  if (observedBundle !== bundle || observedSums !== checksum) throw new Error("primitives client bundle is not reproducible");
} else {
  await writeFile(output, bundle);
  await writeFile(sums, checksum);
}
