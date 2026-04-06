---
name: operational_workflow
description: Build, test, run, and debug commands for the ELF triage tool project
type: project
source: distilled
distilled_from: operational_workflow.md
distilled_at: 2026-04-06T19:30:13.867Z
source_content_hash: a5f64bc13722ef42
stale_after_inactive_days: 30
---

## Commands

- **Install deps:** `pip install -e ".[dev]"`
- **Run tool:** `python -m elftriage <binary>`
- **Run tests:** `pytest`
- **Lint:** `flake8 .`
- **Type check:** `mypy .`
- **Format check:** `black --check .`
- **Format fix:** `black .`
- **Default test binary:** `/bin/ls` (real-world x86_64 ELF available on host)

## Environment

- `gh` (GitHub CLI) is available
- No CI/CD pipeline configured yet
- Package is defined in `pyproject.toml` with `[project.scripts]` entry point
- Skills directory: `.claude/skills/` with `verify/` and `analyze-binary/` subdirs
- Project memories directory: `.claude/project-memories/`
