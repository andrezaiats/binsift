---
name: analyze-binary
description: Run the ELF triage tool against a binary and inspect its output. Use to validate that detection, disassembly, and risk classification are working correctly.
disable-model-invocation: true
---

Run the ELF triage tool against the binary specified in $ARGUMENTS. If no binary is specified, use `/bin/ls` as a default real-world target.

```bash
python -m elftriage $ARGUMENTS
```

Then inspect the output for:

1. **Protection detection** — Are NX, PIE, canary, RELRO, FORTIFY statuses reported?
2. **Import resolution** — Are dangerous libc functions (strcpy, gets, sprintf, etc.) identified via PLT/GOT?
3. **Disassembly** — Are call sites disassembled with surrounding context?
4. **Risk classification** — Are findings ranked by severity (critical, warning, mitigated)?
5. **Report format** — Is the output readable? If `--json` is supported, also run with JSON output and validate the structure.

Report what looks correct and what looks wrong or missing. Compare against the dangerous function database in @docs/main-idea.md.
