"""Backward-slice argument analysis for call sites.

Analyzes the instructions immediately preceding a function call to determine
where each argument register (rdi, rsi, rdx, rcx, r8, r9 per SysV ABI)
was loaded from. This is a lightweight backward slice — not full data-flow
analysis, but enough to classify argument provenance for triage.
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

from elftriage.types import ArgSource, ArgumentInfo, CallSite
from elftriage import dangerous_functions

# SysV AMD64 ABI argument registers in order
_ARG_REGISTERS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

# Registers that indicate stack access
_STACK_REGS = {"rbp", "rsp", "ebp", "esp"}

# Functions whose return value is heap-allocated
_HEAP_ALLOCATORS = {"malloc", "calloc", "realloc", "strdup", "strndup"}

# Functions whose return value is user input
_INPUT_FUNCTIONS = {"read", "recv", "recvfrom", "fgets", "fread", "getline"}

# Max instructions to scan backwards from the call site
_SLICE_DEPTH = 15


def analyze_call_arguments(
    elffile: ELFFile,
    call_sites: list[CallSite],
) -> list[CallSite]:
    """Analyze argument provenance for each call site.

    For each call site, scans backward from the call instruction to
    determine where each argument register was loaded from, then
    classifies the source.

    Args:
        elffile: A parsed ELF file object.
        call_sites: List of call sites to analyze.

    Returns:
        The same call sites with arguments field populated.
    """
    if not call_sites:
        return call_sites

    text_section = elffile.get_section_by_name(".text")
    if text_section is None:
        return call_sites

    text_data = text_section.data()
    text_addr = text_section.header.sh_addr

    # Get .rodata bounds for literal detection
    rodata_start, rodata_end = _get_section_bounds(elffile, ".rodata")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    for site in call_sites:
        # Disassemble a window before the call
        region_start = max(text_addr, site.address - _SLICE_DEPTH * 8)
        offset = region_start - text_addr
        length = site.address - region_start
        if length <= 0:
            continue

        region_data = text_data[offset : offset + length]
        pre_insns = list(md.disasm(region_data, region_start))

        # Determine which arg registers are interesting for this function
        n_args = _interesting_arg_count(site.function_name)
        arg_regs = _ARG_REGISTERS[:n_args]

        arguments: list[ArgumentInfo] = []
        for reg in arg_regs:
            source, detail = _trace_register(pre_insns, reg, rodata_start, rodata_end)
            arguments.append(ArgumentInfo(register=reg, source=source, detail=detail))

        site.arguments = arguments

        # Check format string risk
        fmt_idx = dangerous_functions.get_format_arg_index(site.function_name)
        if fmt_idx is not None and fmt_idx < len(arguments):
            fmt_arg = arguments[fmt_idx]
            if fmt_arg.source != ArgSource.RODATA:
                site.is_format_string_risk = True

    return call_sites


def _trace_register(
    instructions: list[object],
    target_reg: str,
    rodata_start: int,
    rodata_end: int,
) -> tuple[ArgSource, str]:
    """Trace a register backwards through instructions to find its source.

    Scans from the end of the instruction list backwards, looking for
    the most recent instruction that writes to target_reg.

    Args:
        instructions: Pre-call instructions (ordered by address).
        target_reg: The register to trace (e.g. "rdi").
        rodata_start: Start address of .rodata section.
        rodata_end: End address of .rodata section.

    Returns:
        Tuple of (ArgSource classification, human-readable detail).
    """
    target_variants = _register_variants(target_reg)

    for insn in reversed(instructions):
        mnemonic: str = insn.mnemonic  # type: ignore[attr-defined]
        op_str: str = insn.op_str  # type: ignore[attr-defined]

        parts = [p.strip() for p in op_str.split(",")]
        if not parts:
            continue

        dest = parts[0].lower()

        # Check if this instruction writes to our target register
        if dest not in target_variants:
            continue

        # Now classify the source
        if mnemonic in ("mov", "lea", "movzx", "movsxd", "movsx"):
            if len(parts) < 2:
                return ArgSource.UNKNOWN, f"{mnemonic} {op_str}"

            src = parts[1].strip().lower()
            return _classify_source(
                mnemonic, src, insn, rodata_start, rodata_end  # type: ignore[arg-type]
            )

        if mnemonic == "xor" and len(parts) >= 2:
            # xor reg, reg = zero
            if parts[1].strip().lower() in target_variants:
                return ArgSource.UNKNOWN, "zeroed (xor self)"

        if mnemonic == "call":
            # Result of a function call in rax, then moved
            return ArgSource.UNKNOWN, "return value of call"

        return ArgSource.UNKNOWN, f"{mnemonic} {op_str}"

    return ArgSource.UNKNOWN, "not found in slice window"


def _classify_source(
    mnemonic: str,
    src: str,
    insn: object,
    rodata_start: int,
    rodata_end: int,
) -> tuple[ArgSource, str]:
    """Classify the source operand of a mov/lea instruction.

    Args:
        mnemonic: The instruction mnemonic.
        src: The source operand string.
        insn: The capstone instruction object.
        rodata_start: Start of .rodata section.
        rodata_end: End of .rodata section.

    Returns:
        Tuple of (ArgSource, detail string).
    """
    # LEA from stack = stack buffer address
    if mnemonic == "lea":
        if any(r in src for r in ("rbp", "rsp", "ebp", "esp")):
            offset = _extract_offset(src)
            if offset is not None:
                return ArgSource.STACK, f"stack buffer at {src} (lea)"
            return ArgSource.STACK, f"stack address ({src})"

        # LEA with rip = address in data section
        if "rip" in src:
            addr = _resolve_rip_relative(insn)
            if addr is not None:
                if rodata_start <= addr < rodata_end:
                    return ArgSource.RODATA, f"literal at 0x{addr:x} (.rodata)"
                return ArgSource.UNKNOWN, f"data at 0x{addr:x} (lea rip-relative)"

    # MOV from stack memory
    if _is_memory_operand(src):
        if any(r in src for r in _STACK_REGS):
            return ArgSource.STACK, f"stack variable ({src})"
        if "rip" in src:
            addr = _resolve_rip_relative(insn)
            if addr is not None and rodata_start <= addr < rodata_end:
                return ArgSource.RODATA, f"literal at 0x{addr:x} (.rodata)"
            return ArgSource.UNKNOWN, f"global data ({src})"

    # MOV immediate value
    if src.startswith("0x") or src.lstrip("-").isdigit():
        try:
            val = int(src, 0)
            if rodata_start <= val < rodata_end:
                return ArgSource.RODATA, f"pointer to .rodata (0x{val:x})"
        except ValueError:
            pass
        return ArgSource.UNKNOWN, f"immediate value ({src})"

    # MOV from another register — we'd need to trace further
    return ArgSource.REGISTER, f"from register {src}"


def _interesting_arg_count(func_name: str) -> int:
    """Return how many arguments are interesting to analyze for a function.

    Args:
        func_name: The function name.

    Returns:
        Number of arguments to trace (1-3).
    """
    # For most dangerous functions, the first 3 args matter:
    # arg0 (rdi) = dest buffer, arg1 (rsi) = source, arg2 (rdx) = size
    fmt_idx = dangerous_functions.get_format_arg_index(func_name)
    if fmt_idx is not None:
        return fmt_idx + 1

    if func_name in ("gets", "puts"):
        return 1
    if func_name in ("strcpy", "strcat", "strncpy", "strncat"):
        return 3
    if func_name in ("memcpy", "memmove"):
        return 3
    return 3


def _register_variants(reg: str) -> set[str]:
    """Return all size variants of a register name.

    Args:
        reg: The 64-bit register name (e.g. "rdi").

    Returns:
        Set of all name variants (e.g. {"rdi", "edi", "di", "dil"}).
    """
    variants: dict[str, set[str]] = {
        "rdi": {"rdi", "edi", "di", "dil"},
        "rsi": {"rsi", "esi", "si", "sil"},
        "rdx": {"rdx", "edx", "dx", "dl", "dh"},
        "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
        "r8": {"r8", "r8d", "r8w", "r8b"},
        "r9": {"r9", "r9d", "r9w", "r9b"},
        "rax": {"rax", "eax", "ax", "al", "ah"},
    }
    return variants.get(reg, {reg})


def _is_memory_operand(op: str) -> bool:
    """Check if an operand string represents a memory access."""
    return "[" in op and "]" in op


def _extract_offset(src: str) -> int | None:
    """Extract a numeric offset from a memory operand like [rbp - 0x40]."""
    for token in src.replace("[", " ").replace("]", " ").split():
        if token.startswith("0x") or token.startswith("-0x"):
            try:
                return int(token, 16)
            except ValueError:
                pass
    return None


def _resolve_rip_relative(insn: object) -> int | None:
    """Resolve a RIP-relative address from an instruction.

    For RIP-relative addressing, the effective address is:
        instruction_address + instruction_size + displacement

    Args:
        insn: A capstone instruction object.

    Returns:
        The resolved address, or None if it can't be determined.
    """
    try:
        op_str: str = insn.op_str  # type: ignore[attr-defined]
        addr: int = insn.address  # type: ignore[attr-defined]
        size: int = insn.size  # type: ignore[attr-defined]

        # Extract displacement from patterns like [rip + 0x1234] or [rip - 0x1234]
        if "rip + " in op_str:
            disp_str = op_str.split("rip + ")[1].split("]")[0].strip()
            disp = int(disp_str, 0)
            return addr + size + disp
        elif "rip - " in op_str:
            disp_str = op_str.split("rip - ")[1].split("]")[0].strip()
            disp = int(disp_str, 0)
            return addr + size - disp
    except (ValueError, AttributeError, IndexError):
        pass
    return None


def _get_section_bounds(
    elffile: ELFFile,
    section_name: str,
) -> tuple[int, int]:
    """Get the virtual address bounds of a section.

    Args:
        elffile: A parsed ELF file object.
        section_name: The section name (e.g. ".rodata").

    Returns:
        Tuple of (start_address, end_address). Returns (0, 0) if not found.
    """
    section = elffile.get_section_by_name(section_name)
    if section is None:
        return 0, 0
    start = section.header.sh_addr
    return start, start + section.header.sh_size
