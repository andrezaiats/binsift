---
name: codestyle_conventions
description: Coding conventions required for the ELF triage tool Python codebase
type: feedback
source: distilled
distilled_from: codestyle_conventions.md
distilled_at: 2026-04-06T19:30:13.867Z
source_content_hash: 016083203a20db39
stale_after_inactive_days: 90
---

## Python Conventions

- **Type annotations required** on all functions (enforced by mypy)
- **Docstrings required** on all public functions and classes
- **Formatter:** black (line length 88, configured in pyproject.toml)
- **Linter:** flake8 (max line length 88, configured in .flake8)
- **Type checker:** mypy (strict mode, configured in pyproject.toml)
- **Python version:** 3.11+ minimum

## Skill File Conventions

- Skill files live at `.claude/skills/<skill-name>/SKILL.md`
- Frontmatter fields: `name`, `description`, and optionally `disable-model-invocation: true`
- Skills that only run shell commands should set `disable-model-invocation: true`
- Cross-references to design docs use `@docs/<filename>.md` syntax
