# BinSift

A static analysis triage tool for x86_64 ELF binaries. BinSift identifies dangerous libc imports via PLT/GOT resolution, detects binary protections, disassembles call sites, analyzes argument provenance, reconstructs stack frame layouts, and produces an exploitability-ranked report with confidence-tagged conditions.

This is a **triage layer**, not an exploit generator. It narrows the search space for security researchers by answering: *"What can I exploit first, how easily, and what evidence supports that?"*

## Honest scope

BinSift exists in a space full of tools that overclaim. This section tries not to. Read it before deciding whether the tool fits your workflow — it is meant to calibrate expectations, not to sell anything.

### What it is good at

- **First-pass triage of unknown binaries.** If you have fifty ELFs and need to decide which five to open in Ghidra, running BinSift on all of them in a few seconds is a real time saver. The protections panel, dangerous imports list, and call-site context give you the same information you would piece together manually from `checksec`, `readelf`, and `objdump`, in one pass.
- **Explaining *why* a finding is or isn't suspicious.** Every condition carries a confidence level (`CONFIRMED` / `INFERRED` / `UNKNOWN`) and structured `caveats` naming the blind spots of the heuristic that produced it. When promotion to `CONFIRMED` is blocked, the report states exactly which gate failed (`"IR detected pointer escape"`, `"function is recursive"`, `"copy length is not a visible constant"`). This is unusual for tools in this category and, in our view, is the most valuable thing BinSift offers.
- **CTF and teaching contexts.** Small binaries with known vulnerabilities, compiled across multiple protection profiles, are exactly the sweet spot. The output is genuinely didactic.
- **Sanity-check in CI or code review.** "Did this PR really intend to ship a binary without stack canaries and with `RELRO=none`?" is a question BinSift answers without fuss.
- **Building block in larger pipelines.** The JSON output and the capability-warnings plumbing are designed to be consumed by downstream tooling (e.g. feed the top-N findings into angr or a manual review queue).

### What it is *not* good at — and will not be with the current architecture

- **It does not confirm exploits.** Nothing in the tool proves that a given finding is actually reachable with attacker-controlled input. The `copy_size_exceeds_buffer` condition is the closest we get, and it fires rarely in real binaries because compilers inline-size most fixed-length copies away. Users expecting "show me the bug" will be frustrated.
- **Stripped binaries are today's majority, and we handle them poorly.** On `/bin/ls` only 1 of 78 call sites gets IR-based taint, because the built-in function-boundary detector cannot map the containing function for most sites without symbols. A future improvement is to delegate boundary detection to radare2, which is already an optional dependency; today it is a real limitation.
- **The pointer-escape check is aggressively conservative.** Any stack buffer that reaches more than one call in the same function is reported as escaping. `strcpy(buf, …); printf("%s", buf);` is a benign pattern in practice but trips the check and blocks promotion to `CONFIRMED`. The consequence is that in most real-world binaries, `dest_is_stack` almost never reaches `CONFIRMED` and the distinction between `INFERRED` and `CONFIRMED` can feel like noise. This is a deliberate safety choice — the alternative is promoting false positives — but it is a real usability cost.
- **Bug coverage is narrow.** BinSift only looks at unsafe memory operations via known libc imports and format-string risk. It does not reason about heap bugs (UAF, double-free, heap overflow), race conditions, integer overflow, C++ vtables / RTTI, virtual dispatch, function pointers, or signal handlers. Most high-value exploitable bugs in modern software live in those classes, and nothing here helps with them.
- **It does not replace Ghidra, IDA, angr, or a skilled reverse engineer.** Ghidra already decompiles and does reasonable data flow. angr actually checks reachability symbolically. For a single high-stakes binary, those tools are strictly more informative than BinSift. If you were going to open Ghidra anyway, the triage step saves at best thirty seconds of orientation.
- **Format-string `%n` chains, ROP/ret2libc generation, and reachability-by-execution-path are all explicitly out of scope** and always will be. BinSift reports the conditions that make them *possible*; it does not attempt to construct them.

### Where `INFERRED` and `UNKNOWN` are not the same as "false"

A recurring point of confusion: when a condition is `UNKNOWN`, the tool is saying "I declined to commit either way", not "I determined this is false". And when a condition is `INFERRED`, the tool is saying "my heuristic fired, but I am not willing to stake my name on it — here are the caveats". Treat `INFERRED` results as hypotheses to check in your disassembler, not as facts to act on.

### Honest bar for success

BinSift is worth your time if *at least one* of these is true:

1. You triage many binaries and need to prioritise which to inspect manually.
2. You are learning about binary protections, PLT/GOT, and exploitation primitives, and want a tool whose output you can trust to be explanatory rather than aspirational.
3. You want a JSON-producing building block for your own pipelines.

If what you actually want is "tell me where the bug is", use Ghidra, angr, AFL++ or a commercial fuzzer. BinSift will not give you that, and the commit history shows a deliberate refusal to pretend otherwise.

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

Each finding is assessed against a checklist of boolean conditions. Each condition is tagged with a confidence level and, when applicable, a list of structured caveats explaining the limits of that confidence.

| Condition | Weight | Meaning |
|-----------|--------|---------|
| `critical_function` | +10 | Function is in the critical tier (always dangerous) |
| `copy_size_exceeds_buffer` | +9 | Constant copy length is larger than the destination slot's upper-bound size |
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
- **CONFIRMED** — the tool verified this directly from structural binary data: ELF headers, dynamic symbol tables, or section flags. Examples: protections (NX/PIE/canary/RELRO/FORTIFY), function category (critical/warning/mitigated), call-site density.
- **INFERRED** — the tool derived this from a heuristic that has known blind spots. Conditions like `dest_is_stack` and `source_is_input` come from a 15-instruction backward slice that does not model register aliasing or pointer escaping. `copy_size_exceeds_buffer` compares against a slot size that is itself an upper bound (the distance to the next slot, not the buffer's true size).
- **UNKNOWN** — the tool could not determine the condition from the available evidence. This is **not** a soft "false" — it explicitly means the analysis declined to commit.

Conditions that are `INFERRED` carry a `caveats` list explaining *why* the evidence is partial. Examples: `"derived from windowed slice"`, `"aliasing not modeled"`, `"slot size is upper bound (distance to next slot)"`. Caveats appear inline in the text report and as a `caveats` array in JSON output.

### Capability Warnings

When optional analysis backends are unavailable (e.g. call-graph or IR-based taint engines added in later phases), the report opens with a `Capability Warnings` section listing what could not run. This makes it impossible for two environments to silently produce materially different reports for the same binary.

## Reachability (optional)

BinSift can optionally build a call graph via [radare2](https://github.com/radareorg/radare2) and tag each finding with a three-state reachability status. This downranks findings in dead code paths — with important caveats.

Install the extra dependency and ensure `r2` is on your PATH:

```bash
pip install -e ".[callgraph]"
which r2   # radare2 must be installed separately
```

When the backend is available, each finding gains a `Reachability` tag in the text report and a `reachability` field in the JSON output:

- **REACHABLE** — the call graph shows a direct-call path from an entry point (`main`, `_start`, `entry0`) to the finding's containing function. This is reported with `INFERRED` confidence because the basic `aaa` extraction misses indirect calls, callbacks, vtables, and `.init`/`.fini` array handlers.
- **UNREACHABLE** — reserved for positive proof that the code cannot run (e.g. a symbol in a discarded section). The basic r2 call graph never emits this state, but it is available for future backends. When set, applies a small score penalty.
- **UNKNOWN** — the default, and also the result when no static path is found. **Absence of a call-graph edge is never treated as proof of dead code.**

When the backend is unavailable, the top-level `Capability Warnings` section names the gap, each finding's `reachable_from_entry` condition shows `[UNKNOWN]` with a caveat telling the user exactly which extras to install, and no scoring decision depends on reachability.

## IR-based taint analysis (optional)

BinSift can optionally lift each function containing a dangerous call site to [Ghidra P-Code](https://ghidra.re/courses/languages/html/pcoderef.html) via [pypcode](https://github.com/angr/pypcode), then run a backward reaching-definitions analysis on the SSA-friendly IR. P-Code normalises x86 register aliasing (`eax`/`rax`), exposes stack arithmetic as plain `RBP + const`, and lets the analyser see through patterns the windowed slice cannot — most importantly the very common `lea rax, [rbp - N]; mov rdi, rax` pair, which leaves the slice classifying `rdi` as `register` instead of `stack`.

Install the extra dependency:

```bash
pip install -e ".[ir]"
```

When the IR backend is available and the call site has a known containing function, taint analysis runs in place of the slice. Each call site records its `taint_method` (`"ir"` or `"slice"`) and, for IR sites with a stack destination, a `stack_dest_escapes` flag. The text report shows a `Taint backend:` line per finding so it is obvious which backend produced the result.

The IR backend also enables the only path by which `dest_is_stack` can be promoted from `INFERRED` to `CONFIRMED`. Promotion requires **all** of the following:

1. The argument came from the IR backend (not the slice).
2. The IR confirmed the destination's stack slot does not escape to any other call within the same function.
3. The containing function is not directly recursive (so the slot is not effectively reused across invocations).
4. A constant `copy_size` is visible at the call site.

If any of these fails, the condition stays `INFERRED` and the report explains exactly which gate blocked promotion (e.g. `"IR detected pointer escape — slot may be aliased"`, `"function is recursive — slot reused across calls"`, `"copy length is not a visible constant"`). Slice-derived results never promote.

When the IR backend is unavailable, the top-level `Capability Warnings` section names the gap, every per-finding `Taint backend:` line says `slice (IR-based taint unavailable)`, and no `dest_is_stack` condition can ever reach `CONFIRMED`.

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
