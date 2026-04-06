# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ELF Vulnerability Triage Tool — a Python static analysis scanner for x86_64 ELF binaries. It identifies dangerous libc imports via PLT/GOT resolution, detects binary protections (NX, PIE, canaries, RELRO, FORTIFY_SOURCE), disassembles call sites with capstone, and produces a ranked risk report (text + JSON).

This is a triage layer, not an exploit generator. It narrows the search space for security researchers.

See @docs/main-idea.md for the full design document.

## Build and Run

```bash
# Install dependencies
pip install -e ".[dev]"

# Run the tool
python -m elftriage <binary>

# Run tests
pytest

# Linting and formatting
black --check .
flake8 .
mypy .

# Format code
black .
```

## Architecture

CLI Interface → ELF Parser (pyelftools) → three parallel modules:
- **Protection Detector** — NX, PIE, canary, RELRO, FORTIFY
- **Import Resolver** — .rela.plt, .dynstr, .dynsym for dangerous libc calls
- **Disassembly Engine** — capstone x86_64 call-site context

These feed into a Risk Classifier (heuristic ranking) → Report Generator (text/JSON).

## Technology Stack

- Python 3.11+, pip with pyproject.toml
- pyelftools (ELF parsing), capstone (disassembly), argparse (CLI)
- pytest (testing), flake8 (linting), black (formatting), mypy (type checking)

## Coding Conventions

- All functions must have full type annotations.
- All public functions and classes must have docstrings.
- Use black for formatting (default settings).
- Target scope is x86_64 dynamically linked ELF binaries only.

## Directory Map

| Directory | Purpose |
|-----------|---------|
| docs/ | Design documents and project specifications |
