---
name: verify
description: Run the full quality check pipeline — formatting, linting, type checking, and tests. Use after making changes to confirm nothing is broken.
---

Run the following commands in order. Stop and report at the first failure:

1. **Format check:** `black --check .`
2. **Lint:** `flake8 .`
3. **Type check:** `mypy .`
4. **Tests:** `pytest`

If all pass, report success. If any fail, show the full error output and suggest fixes.
