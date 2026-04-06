---
name: recipes_development
description: Multi-step workflows for project setup and validation in the ELF triage tool
type: reference
source: distilled
distilled_from: recipes_development.md
distilled_at: 2026-04-06T19:30:13.867Z
source_content_hash: 49bf7bd165f85e3a
stale_after_inactive_days: 90
---

## Recipe: Full quality check

1. `black --check .` — formatting
2. `flake8 .` — linting
3. `mypy .` — type checking
4. `pytest` — tests

Stop and report on first failure. All four must pass before committing.

## Recipe: Validate tool output against a binary

1. `python -m elftriage /bin/ls` (or target binary)
2. Check: protection flags reported (NX, PIE, canary, RELRO, FORTIFY)
3. Check: dangerous imports listed with severity tier
4. Check: call-site disassembly shown with context
5. Check: risk classification ranks findings
6. Optionally run with `--json` and validate JSON structure
