# BinSift

A static analysis triage tool for x86_64 ELF binaries. BinSift identifies dangerous libc imports via PLT/GOT resolution, detects binary protections, disassembles call sites, and produces a ranked risk report.

This is a **triage layer**, not an exploit generator. It narrows the search space for security researchers by answering: *"Where should I look first in this binary?"*

## Features

- **Binary protection detection** — NX, PIE, stack canaries, RELRO (none/partial/full), FORTIFY_SOURCE
- **Dangerous import resolution** — parses `.rela.plt`, `.dynsym`, `.dynstr` to identify unsafe libc calls (`gets`, `strcpy`, `sprintf`, `memcpy`, etc.)
- **Fortified variant detection** — identifies `__*_chk` symbols indicating FORTIFY_SOURCE hardening
- **Call-site disassembly** — shows instruction context around each dangerous call using capstone
- **Heuristic risk ranking** — scores findings by function severity, protection status, and call frequency
- **Dual output** — human-readable text report and structured JSON for automation

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Analyze a binary (text report)
elftriage /bin/ls

# JSON output
elftriage /bin/ls --json

# Write report to file
elftriage /bin/ls --output report.txt

# Adjust disassembly context window
elftriage /bin/ls --context-lines 10
```

Or run as a module:

```bash
python -m elftriage /bin/ls
```

## Example Output

```
======================================================================
ELF Vulnerability Triage Report
======================================================================
Binary: /bin/ls

----------------------------------------
Binary Protections
----------------------------------------
  NX (No Execute):  Yes
  PIE (Position Independent): Yes
  Stack Canary:     Yes
  RELRO:            PARTIAL
  FORTIFY_SOURCE:   Yes

----------------------------------------
Summary
----------------------------------------
  total_dangerous_imports: 7
  critical: 1
  warning: 3
  mitigated: 3
  total_call_sites: 45

----------------------------------------
Findings (ranked by severity)
----------------------------------------
  [1] memcpy (WARNING)
      Risk: Dangerous if size is user-controlled
      PLT address: 0x43f0
      Severity score: 62.5
      Call sites: 24
      --- Call at 0x7437 ---
           0x7420: cmp rax, 0x1fff
           0x7426: ja 0x76b9
           0x742c: mov rdi, qword ptr [rsp + 0x10]
           0x7431: mov rdx, rbx
           0x7434: mov rsi, rbp
       >>> 0x7437: call 0x43f0
           ...
```

## Target Scope

- **Architecture:** x86_64 only
- **Format:** ELF (dynamically linked)
- **Bug class:** Unsafe memory operations from known-dangerous libc imports

## Risk Classification

| Tier | Functions | Meaning |
|------|-----------|---------|
| **Critical** | `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf` | Always dangerous, no bounds checking |
| **Warning** | `memcpy`, `memmove`, `strncpy`, `strncat`, `snprintf`, `scanf`, `fscanf`, `sscanf`, `read`, `recv` | Context-dependent risk |
| **Mitigated** | `__strcpy_chk`, `__memcpy_chk`, `__sprintf_chk`, etc. | FORTIFY_SOURCE-protected variants |

## Development

```bash
# Run tests
pytest

# Formatting
black .

# Linting
flake8 elftriage/ tests/

# Type checking
mypy elftriage/
```

## Tech Stack

- **Python 3.11+**
- [pyelftools](https://github.com/eliben/pyelftools) — ELF parsing
- [capstone](https://www.capstone-engine.org/) — x86_64 disassembly
- argparse — CLI

## License

[MIT](LICENSE)
