---
name: domain_glossary
description: Project-specific terms for the ELF vulnerability triage tool
type: reference
source: distilled
distilled_from: domain_glossary.md
distilled_at: 2026-04-06T19:30:13.867Z
source_content_hash: a4456e2c88050ffd
stale_after_inactive_days: 180
---

## Terms

- **ELF triage tool** — the project name; static analysis scanner for x86_64 ELF binaries, not an exploit generator
- **PLT/GOT resolution** — technique used to identify which libc functions a binary imports; reads `.rela.plt`, `.dynstr`, `.dynsym` sections
- **Dangerous function** — libc function known to be unsafe (e.g. `gets`, `strcpy`, `sprintf`); classified as Critical or Warning
- **Fortified variant** — compiler-generated safe replacement (e.g. `__strcpy_chk`); presence indicates FORTIFY_SOURCE hardening; classified as Mitigated
- **Three-tier risk model** — Critical (always dangerous) / Warning (context-dependent) / Mitigated (fortified `__*_chk` variants)
- **Protection detection** — checking binary headers/sections for NX, PIE, stack canary, RELRO, FORTIFY_SOURCE flags
- **Call-site context** — disassembly of a few instructions surrounding each dangerous function call, not full binary disassembly
- **pyelftools** — Python library used for ELF section/symbol parsing
- **capstone** — Python disassembly library used for x86_64 call-site disassembly
