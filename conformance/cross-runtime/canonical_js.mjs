#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { canonicalize, parseJson } from "../../js/lib/canonical-json.mjs";
process.stdout.write(canonicalize(parseJson(await readFile(process.argv[2],"utf8"))));
