# BinSift

A static analysis triage tool for x86_64 ELF binaries. BinSift identifies dangerous libc imports via PLT/GOT resolution, detects binary protections, disassembles call sites, analyzes argument provenance, reconstructs stack frame layouts, and produces an exploitability-ranked report with confidence-tagged conditions.

This is a **triage layer**, not an exploit generator. It narrows the search space for security researchers by answering: *"What can I exploit first, how easily, and what evidence supports that?"*

## Features

- **Binary protection detection** — NX, PIE (with DF_1_PIE validation), stack canaries, RELRO (none/partial/full), FORTIFY_SOURCE
- **Dangerous import resolution** — parses `.rela.plt`, `.dynsym`, `.dynstr` to identify unsafe libc calls (`gets`, `strcpy`, `sprintf`, `memcpy`, etc.), with correct PLT/GOT address mapping
- **Format string detection** — identifies `printf`, `fprintf`, `syslog` and related calls where the format argument is not a string literal
- **Fortified variant detection** — identifies `__*_chk` symbols indicating FORTIFY_SOURCE hardening
- **Call-site disassembly** — shows instruction context around each dangerous call, resolving both direct calls and indirect calls through the GOT
- **Argument analysis** — backward-slice tracing of argument registers (rdi, rsi, rdx) to classify sources as stack, heap, .rodata, input, or register
- **Stack frame reconstruction** — maps all stack references (rbp and rsp-relative) within each function to build a slot layout, estimate inter-slot distances, and compute distance to the return address
- **Function boundary detection** — maps call sites to containing functions via symbol tables or prologue heuristics
- **Exploitability conditions with confidence** — each finding gets a checklist of boolean conditions (no_canary, dest_is_stack, source_is_input, etc.) tagged as CONFIRMED, INFERRED, or UNKNOWN
- **Exploit primitive classification** — findings are classified by the type of primitive they may yield: flow control hijack, information leak, arbitrary write, or denial of service
- **Exploit scenario grouping** — findings are grouped by exploit primitive so researchers see actionable scenarios ("stack overflow → flow control") rather than isolated function warnings
- **Additive severity scoring** — each satisfied condition adds weighted points (replacing multiplicative scoring), producing stable and auditable rankings
- **Exploitability notes** — cross-references argument sources with binary protections and stack frame data to produce actionable risk chains
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
Binary: ./vuln_stack_overflow

----------------------------------------
Binary Protections
----------------------------------------
  NX (No Execute):           No
  PIE (Position Independent): No
  Stack Canary:              No
  RELRO:                     NONE
  FORTIFY_SOURCE:            No

----------------------------------------
Findings (ranked by severity)
----------------------------------------
  [1] strcpy (CRITICAL)
      Risk: No length limit, classic overflow source
      PLT address: 0x401030
      Severity score: 33.0
      Call sites: 1
      Exploitability:
        ! strcpy with no stack canary: stack buffer overflow
          can overwrite return address without detection
        ! No PIE: addresses are predictable, simplifying
          ROP/ret2libc exploitation of strcpy
        ! No NX: shellcode on the stack is executable,
          strcpy overflow could lead to direct code execution
        ! strcpy writes to a stack buffer: overflow can corrupt
          the saved return pointer and control flow
        ! Buffer is 72 bytes from return address
          (confirmed via stack frame analysis)
        ! HIGH RISK: stack-targeted write + no canary +
          critical function = classic exploitable stack overflow
        ! EXPLOIT CHAIN: stack overflow → overwrite return
          address (no canary) → jump to known address (no PIE)
      Exploit primitive: FLOW CONTROL
      Conditions:
        [CONFIRMED]  ✓ no_canary (Stack canary is absent)
        [CONFIRMED]  ✓ no_pie (PIE is disabled)
        [CONFIRMED]  ✓ no_nx (NX is disabled)
        [CONFIRMED]  ✓ no_relro (RELRO is none)
        [CONFIRMED]  ✓ dest_is_stack (Destination points to a stack buffer)
        [CONFIRMED]  ✗ source_is_input (No input-sourced arguments detected)
        [CONFIRMED]  ✓ critical_function (strcpy is always dangerous)
        ...

------------------------------------------
Exploit Scenarios (by ease of exploitation)
------------------------------------------

  [FLOW CONTROL] Control Flow Hijack
  One or more findings may allow overwriting a return address
  or function pointer to redirect execution.

  Conditions:
    [CONFIRMED]  ✓ no_canary (Stack canary is absent)
    [CONFIRMED]  ✓ dest_is_stack (Destination points to a stack buffer)
    [CONFIRMED]  ✓ no_pie (PIE is disabled)
    [CONFIRMED]  ✓ no_nx (NX is disabled)
    [CONFIRMED]  ✓ critical_function (strcpy is always dangerous)

  Satisfied: 7/10 confirmed, 0/10 unknown

  Related findings:
    - strcpy (severity: 33.0) — 1 call site
    - gets (severity: 33.0) — 1 call site

  ---
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
     │  ├── stack buffer?  ├── .rodata literal?
     │  ├── input source?  └── format string risk?
     │
     ▼
Stack Frame Mapper ── per-function stack layout
     │  ├── rbp-relative and rsp-relative slot detection
     │  ├── inter-slot distance estimation
     │  └── distance to return address (rbp + 8)
     │
     ▼
Risk Classifier ── additive condition-based scoring
     │  ├── builds ExploitCondition checklist per finding
     │  ├── tags each condition as CONFIRMED / INFERRED / UNKNOWN
     │  ├── determines exploit primitive (flow_control, info_leak, ...)
     │  └── generates exploitability notes with stack frame data
     │
     ▼
Scenario Builder ── groups findings by exploit primitive
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

## Exploitability Conditions

Each finding is assessed against 10 boolean conditions. Each condition is tagged with a confidence level indicating whether the tool confirmed it from the binary, inferred it heuristically, or could not determine it.

| Condition | Weight | Meaning |
|-----------|--------|---------|
| `critical_function` | +10 | Function is in the critical tier (always dangerous) |
| `no_canary` | +8 | Stack canary is absent |
| `format_string_controlled` | +8 | Format argument is not a string literal |
| `no_nx` | +7 | NX disabled (stack is executable) |
| `dest_is_stack` | +7 | Destination argument (rdi) points to a stack buffer |
| `source_is_input` | +6 | An argument comes from an input source (read/recv) |
| `no_pie` | +5 | PIE disabled (predictable addresses) |
| `no_relro` | +3 | RELRO is none |
| `multiple_call_sites` | +2 | 3 or more call sites exist |
| `fortified` | −5 | Function is a FORTIFY_SOURCE variant (reduces score) |

The severity score is the sum of weights for all satisfied conditions, clamped to a minimum of 0.

**Confidence levels:**
- **CONFIRMED** — the tool verified this directly from binary data (e.g., canary detected by checking for `__stack_chk_fail` in `.dynsym`)
- **INFERRED** — the tool inferred this from heuristics (e.g., stack destination detected via backward slicing, which may miss register aliasing)
- **UNKNOWN** — the tool could not determine this condition (e.g., destination could not be traced within the slice window)

## Exploit Primitives

Findings are classified by the type of exploit primitive they may enable, then grouped into scenarios:

| Primitive | Trigger conditions | Meaning |
|-----------|-------------------|---------|
| **Flow Control** | Critical function or stack destination, not mitigated | Potential to overwrite return address or function pointer |
| **Arbitrary Write** | Format string controlled + no RELRO | Format string `%n` can write to arbitrary memory |
| **Info Leak** | Format string controlled | Format string can leak stack/heap data, defeating ASLR |
| **DoS** | Some conditions satisfied but no clear exploit path | May cause crashes or undefined behavior |

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

# Build test binaries (requires gcc)
bash tests/binaries/build.sh

# Run against a test binary
elftriage tests/binaries/bin/vuln_stack_overflow_gcc_noprotect
```

### Test Binary Matrix

The test suite includes C programs with known vulnerabilities compiled across different protection profiles:

| Source | Vulnerability | Purpose |
|--------|--------------|---------|
| `vuln_stack_overflow.c` | `strcpy`, `gets`, `strcat` | Validate stack overflow detection |
| `vuln_format_string.c` | `printf(user_input)` | Validate format string detection |
| `safe_program.c` | `snprintf` only | Validate no false positives |

Each is compiled in three profiles:
- **noprotect** — `-O0 -fno-stack-protector -no-pie -z execstack -z norelro -g`
- **protect** — `-O2 -fstack-protector-all -pie -D_FORTIFY_SOURCE=2 -z relro -z now -g`
- **O2_stripped** — `-O2 -fno-stack-protector -no-pie -s` (stripped, no debug info)

## Tech Stack

- **Python 3.11+**
- [pyelftools](https://github.com/eliben/pyelftools) — ELF parsing
- [capstone](https://www.capstone-engine.org/) — x86_64 disassembly
- argparse — CLI

## License

[MIT](LICENSE)
