# Replay CLI

```text
npm run replay -- --input TRANSCRIPT.json|jsonl \
  --work ABSOLUTE_WORK_URI [--pretty]
```

| Exit | Meaning |
| ---: | --- |
| `0` | Complete, active, final projection |
| `1` | Valid but incomplete or non-active projection |
| `2` | Invalid arguments or transcript |

JSON is canonical by default. `--pretty` changes presentation only. The
replayer reads local files, performs no network access and grants no authority.
