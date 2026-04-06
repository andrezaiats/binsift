# BinSift

A static analysis triage tool for x86_64 ELF binaries. BinSift identifies dangerous libc imports via PLT/GOT resolution, detects binary protections, disassembles call sites, analyzes argument provenance, and produces a ranked risk report with exploitability context.

This is a **triage layer**, not an exploit generator. It narrows the search space for security researchers by answering: *"Where should I look first in this binary, and why?"*

## Features

- **Binary protection detection** — NX, PIE (with DF_1_PIE validation), stack canaries, RELRO (none/partial/full), FORTIFY_SOURCE
- **Dangerous import resolution** — parses `.rela.plt`, `.dynsym`, `.dynstr` to identify unsafe libc calls (`gets`, `strcpy`, `sprintf`, `memcpy`, etc.), with correct PLT/GOT address mapping
- **Format string detection** — identifies `printf`, `fprintf`, `syslog` and related calls where the format argument is not a string literal
- **Fortified variant detection** — identifies `__*_chk` symbols indicating FORTIFY_SOURCE hardening
- **Call-site disassembly** — shows instruction context around each dangerous call, resolving both direct calls and indirect calls through the GOT
- **Argument analysis** — backward-slice tracing of argument registers (rdi, rsi, rdx) to classify sources as stack, heap, .rodata, input, or register
- **Function boundary detection** — maps call sites to containing functions via symbol tables or prologue heuristics
- **Exploitability notes** — cross-references argument sources with binary protections to produce actionable risk chains (e.g., "stack write + no canary + no PIE = classic exploit path")
- **Heuristic risk ranking** — scores findings by function severity, protection status, call frequency, and argument provenance
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
  NX (No Execute):           Yes
  PIE (Position Independent): Yes
  Stack Canary:              Yes
  RELRO:                     PARTIAL
  FORTIFY_SOURCE:            Yes

----------------------------------------
Summary
----------------------------------------
  Total Dangerous Imports: 9
  Critical: 1
  Warning: 3
  Format String: 0
  Mitigated: 5
  Total Call Sites: 78
  Format String Risks: 0
  Functions Detected: 6

----------------------------------------
Findings (ranked by severity)
----------------------------------------
  [1] memcpy (WARNING)
      Risk: Dangerous if size is user-controlled
      PLT address: 0x43f0
      GOT address: 0x241e0
      Severity score: 87.5
      Call sites: 24
      Exploitability:
        ! memcpy writes to a stack buffer: overflow can corrupt
          the saved return pointer and control flow
      --- Call at 0x7437 ---
      [rdi] stack (stack variable (qword ptr [rsp + 0x10]))
      [rsi] register (from register rbp)
      [rdx] register (from register rbx)
           0x7420: cmp rax, 0x1fff
           0x7426: ja 0x76b9
           0x742c: mov rdi, qword ptr [rsp + 0x10]
           0x7431: mov rdx, rbx
           0x7434: mov rsi, rbp
       >>> 0x7437: call 0x43f0
           0x743c: mov byte ptr [rsp + 0x2f], 0
           ...
```

## Analysis Pipeline

```
CLI Interface
     │
     ▼
ELF Parser (pyelftools) ── validate x86_64, dynamic
     │
     ├──► Protection Detector ── NX, PIE, canary, RELRO, FORTIFY
     ├──► Import Resolver ── .rela.plt → PLT/GOT → dangerous function DB
     ├──► Function Detector ── symbols or prologue heuristics
     │
     ▼
Disassembly Engine (capstone)
     │  ├── direct calls (call 0xaddr)
     │  └── indirect GOT calls (call [rip + offset])
     │
     ▼
Argument Analyzer ── backward slice of rdi/rsi/rdx
     │  ├── stack buffer?
     │  ├── .rodata literal?
     │  ├── input source (read/recv)?
     │  └── format string risk?
     │
     ▼
Risk Classifier ── severity = base × protections × args × sites
     │  └── generates exploitability notes
     │
     ▼
Report Generator ── text or JSON
```

## Target Scope

- **Architecture:** x86_64 only
- **Format:** ELF (dynamically linked)
- **Bug classes:** Unsafe memory operations, format string vulnerabilities

## Risk Classification

| Tier | Functions | Meaning |
|------|-----------|---------|
| **Critical** | `gets`, `strcpy`, `strcat`, `sprintf`, `vsprintf` | Always dangerous, no bounds checking |
| **Warning** | `memcpy`, `memmove`, `strncpy`, `strncat`, `snprintf`, `scanf`, `fscanf`, `sscanf`, `read`, `recv` | Context-dependent risk |
| **Format String** | `printf`, `fprintf`, `dprintf`, `syslog`, `vprintf`, `vfprintf` | Dangerous if format arg is not a literal |
| **Mitigated** | `__strcpy_chk`, `__memcpy_chk`, `__printf_chk`, etc. | FORTIFY_SOURCE-protected variants |

## Argument Source Classification

The argument analyzer traces register assignments backward from each call site to classify where function arguments originate:

| Source | Meaning | Risk Impact |
|--------|---------|-------------|
| **stack** | Argument loaded from a stack offset (rbp/rsp) | Buffer overflow can corrupt return address |
| **rodata** | Pointer to `.rodata` section (string literal) | Generally safe — not attacker-controlled |
| **input** | Return value from `read`/`recv`/`fgets` | Attacker-controlled data |
| **heap** | Return value from `malloc`/`calloc` | Heap overflow possible |
| **register** | Passed through from another register | Needs further tracing |
| **unknown** | Could not determine within the slice window | Conservative — treated as potentially risky |

## Development

```bash
# Run tests
pytest

# Full quality check
black --check . && flake8 . && mypy . && pytest

# Format code
black .
```

## Tech Stack

- **Python 3.11+**
- [pyelftools](https://github.com/eliben/pyelftools) — ELF parsing
- [capstone](https://www.capstone-engine.org/) — x86_64 disassembly
- argparse — CLI

## License

[MIT](LICENSE)
