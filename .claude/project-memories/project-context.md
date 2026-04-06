---
name: project-context
description: Auto-scanned project stack, structure, and tooling configuration
type: project
source: scan-project
scanned_at: 2026-04-06T00:00:00Z
stale_after_inactive_days: 30
---

### Project Structure
- Greenfield project — no source code yet, only design document
- Root contains: `CLAUDE.md`, `docs/`
- `docs/main-idea.md` — full design specification and architecture
- `.claude/skills/verify/` — quality check pipeline skill
- `.claude/skills/analyze-binary/` — binary analysis validation skill
- No dependency manifest (pyproject.toml) created yet
- No CI/CD pipeline configured yet

### Architecture & Design
- Three-tier risk classification: Critical (always dangerous, e.g. `gets`, `strcpy`), Warning (context-dependent, e.g. `memcpy`, `scanf`), Mitigated (fortified variants like `__strcpy_chk`)
- Dangerous function detection works via PLT/GOT resolution (.rela.plt + .dynstr + .dynsym)
- Fortified variant detection (`__*_chk` symbols) used as evidence of FORTIFY_SOURCE hardening
- Disassembly provides surrounding context of each dangerous call site, not full binary disassembly
- Risk classifier applies heuristics — does not confirm exploitability

### Known Limitations & Plans
- MVP: x86_64 dynamically linked ELF only — no static binaries, no other architectures
- Out of scope for MVP: heap bugs, UAF, race conditions, format strings, indirect calls, vtable dispatch, obfuscated/packed binaries, CFG construction
- Validation requires compiled C test binaries (vulnerable + hardened variants) plus real system binaries
- Post-MVP plans: format string detection, basic data-flow tracking, angr integration for reachability, static binary support via byte-signature matching, heap analysis, SARIF output for CI/CD

_Re-run `/scan-project` after significant changes to stack, structure, or tooling._
