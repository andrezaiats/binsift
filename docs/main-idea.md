# ELF Vulnerability Triage Tool

A static analysis triage tool for x86_64 ELF binaries that identifies potentially dangerous
patterns, resolves unsafe library calls, and produces a ranked risk report.

## What This Tool Is

A **fast, focused triage layer** that answers the question: "Where should a security researcher
look first in this binary?" It combines existing tooling with custom heuristics into a single
workflow that produces a clear, actionable report.

This is **not** an exploit generator, a symbolic execution engine, or a replacement for
Ghidra/IDA/angr. It is a front-line scanner that narrows the search space.

## What This Tool Is Not

- It does **not** confirm exploitability. It classifies suspicious patterns and ranks risk.
- It does **not** generate payloads, ROP chains, or working exploits.
- It does **not** perform symbolic execution or data-flow analysis.
- It does **not** replace manual reverse engineering for complex targets.

## Goals

1. **Parse ELF structure** — extract sections, segments, symbol tables, and dynamic linking
   metadata using `pyelftools`.
2. **Detect binary protections** — report on NX, ASLR/PIE, stack canaries, RELRO, and
   FORTIFY_SOURCE status.
3. **Resolve dangerous imports via PLT/GOT** — parse `.rela.plt` and `.dynstr` to identify
   calls to unsafe libc functions (`strcpy`, `gets`, `sprintf`, `memcpy`, etc.), including
   fortified variants (`__strcpy_chk`, `__memcpy_chk`).
4. **Disassemble call sites** — use `capstone` to disassemble the surrounding context of each
   dangerous call, showing what happens before and after.
5. **Classify and rank risk** — apply heuristics to rank findings by severity (e.g., `gets` is
   always dangerous; `strcpy` depends on context; `__strcpy_chk` is mitigated).
6. **Produce a structured report** — output findings in a human-readable format with optional
   JSON export for automation.

## Target Scope (MVP)

- **Architecture:** x86_64 only.
- **Binary format:** ELF (dynamically linked).
- **Bug class:** Unsafe memory operations from known-dangerous libc imports.
- **Protections:** Detect and report, but do not attempt to bypass.

### Explicitly Out of Scope for MVP

- Heap overflows, use-after-free, race conditions, format string bugs.
- Statically linked binaries (no PLT to resolve).
- Indirect calls, vtable dispatch, function pointer analysis.
- Obfuscated, packed, or JIT-compiled binaries.
- CFG construction or path reachability analysis.
- C++ exception handling, DWARF unwinding.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   CLI Interface                  │
│              (argument parsing, output)           │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│               ELF Parser Layer                   │
│     (pyelftools: sections, segments, symbols)    │
└────────────────────┬────────────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
┌──────────┐  ┌────────────┐  ┌──────────────┐
│ Protection│  │   Import   │  │  Disassembly │
│ Detector  │  │  Resolver  │  │    Engine    │
│           │  │            │  │  (capstone)  │
│ NX, PIE,  │  │ .rela.plt  │  │              │
│ canary,   │  │ .dynstr    │  │ call-site    │
│ RELRO,    │  │ .dynsym    │  │ context      │
│ FORTIFY   │  │            │  │              │
└─────┬─────┘  └─────┬──────┘  └──────┬───────┘
      │              │                │
      └──────────────┼────────────────┘
                     ▼
        ┌────────────────────────┐
        │    Risk Classifier     │
        │                        │
        │  heuristic ranking of  │
        │  findings by severity  │
        └────────────┬───────────┘
                     ▼
        ┌────────────────────────┐
        │    Report Generator    │
        │                        │
        │  text / JSON output    │
        └────────────────────────┘
```

## Technology Stack

| Component        | Tool / Library   | Why                                              |
|------------------|------------------|--------------------------------------------------|
| Language         | Python 3.11+     | Rich ecosystem for binary analysis                |
| ELF parsing      | pyelftools       | Mature, pure-Python, handles all ELF structures   |
| Disassembly      | capstone         | Fast, lightweight, supports x86_64 natively       |
| CLI              | argparse         | Standard library, no extra dependencies            |
| Report output    | Built-in + JSON  | No dependencies needed                            |

## Dangerous Function Database

### Always Dangerous (Critical)

| Function | Risk                                      |
|----------|-------------------------------------------|
| `gets`   | No bounds checking, always exploitable     |
| `strcpy` | No length limit, classic overflow source   |
| `strcat` | No length limit on concatenation           |
| `sprintf`| No output bounds checking                  |
| `vsprintf`| No output bounds checking                 |

### Context-Dependent (Warning)

| Function  | Risk                                                    |
|-----------|---------------------------------------------------------|
| `memcpy`  | Dangerous if size is user-controlled                     |
| `memmove` | Same as memcpy                                           |
| `strncpy` | Safe-ish, but silent truncation can cause logic bugs     |
| `strncat` | Off-by-one errors are common                             |
| `snprintf`| Usually safe, but return value misuse can cause issues   |
| `scanf`   | `%s` without width is unbounded                          |
| `fscanf`  | Same as scanf                                            |
| `sscanf`  | Same as scanf                                            |
| `read`    | Safe by itself, but buffer sizing matters                |
| `recv`    | Same as read                                             |

### Fortified Variants (Mitigated)

| Function         | Meaning                                      |
|------------------|----------------------------------------------|
| `__strcpy_chk`   | FORTIFY_SOURCE-protected strcpy               |
| `__memcpy_chk`   | FORTIFY_SOURCE-protected memcpy               |
| `__sprintf_chk`  | FORTIFY_SOURCE-protected sprintf              |
| `__gets_chk`     | FORTIFY_SOURCE-protected gets (still risky)   |

Detection of fortified variants tells us the binary was compiled with hardening,
which is useful context for the risk report.

## Validation Strategy

1. **Vulnerable test binaries** — small C programs with known buffer overflows,
   compiled with `-fno-stack-protector -no-pie -z execstack` to verify detection.
2. **Hardened test binaries** — same programs compiled with full protections to verify
   the tool correctly reports mitigations.
3. **Real system binaries** — run against `/bin/ls`, `/usr/bin/cat`, etc. to validate
   that PLT resolution and disassembly work on stripped, hardened, real-world targets.

## Future Directions (Post-MVP)

- Format string vulnerability detection (`printf` with non-literal format argument).
- Basic data-flow tracking to determine if copy sizes are stack-derived.
- Integration with `angr` for reachability confirmation of flagged call sites.
- Support for statically linked binaries via byte-signature matching.
- Heap analysis for `malloc`/`free` patterns (double-free, UAF heuristics).
- SARIF output for integration with CI/CD pipelines.
