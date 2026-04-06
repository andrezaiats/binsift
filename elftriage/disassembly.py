"""Capstone-based disassembly engine for call-site context extraction.

Supports both direct calls (call 0xaddr) and indirect calls through the
GOT (call qword ptr [rip + offset]) for resolving PLT/GOT targets.
Uses streaming disassembly to avoid materializing the entire .text section.
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const
from elftools.elf.elffile import ELFFile

from elftriage.types import (
    CallSite,
    DangerousImport,
    DisassemblyLine,
    FunctionBoundary,
)
from elftriage.functions import find_containing_function


def disassemble_call_sites(
    elffile: ELFFile,
    imports: list[DangerousImport],
    context_lines: int = 5,
    functions: list[FunctionBoundary] | None = None,
) -> list[CallSite]:
    """Find and disassemble call sites for dangerous imports.

    Two-pass approach:
    1. Scan .text for call/jmp instructions targeting PLT or GOT entries.
    2. Re-disassemble only the context windows around each hit.

    Handles both direct calls (target is PLT address) and indirect calls
    through the GOT (call [rip + offset] where the memory target is a
    GOT entry associated with a dangerous import).

    Args:
        elffile: A parsed ELF file object.
        imports: List of dangerous imports with PLT/GOT addresses.
        context_lines: Number of instructions before/after each call.
        functions: Optional list of function boundaries for labeling.

    Returns:
        List of call sites with disassembly context.
    """
    if not imports:
        return []

    text_section = elffile.get_section_by_name(".text")
    if text_section is None:
        return []

    text_data = text_section.data()
    text_addr = text_section.header.sh_addr

    # Build lookup maps for both PLT and GOT targets
    plt_targets: dict[int, DangerousImport] = {imp.plt_address: imp for imp in imports}
    got_targets: dict[int, DangerousImport] = {
        imp.got_address: imp for imp in imports if imp.got_address != 0
    }

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Pass 1: find all call sites by scanning the full .text section
    hit_locations: list[tuple[int, DangerousImport]] = []

    for insn in md.disasm(text_data, text_addr):
        if insn.mnemonic not in ("call", "jmp"):
            continue

        imp = _resolve_call_target(insn, plt_targets, got_targets)
        if imp is not None:
            hit_locations.append((insn.address, imp))

    if not hit_locations:
        return []

    # Pass 2: re-disassemble context windows around each hit
    call_sites: list[CallSite] = []
    func_list = functions or []

    for hit_addr, imp in hit_locations:
        context = _extract_context(md, text_data, text_addr, hit_addr, context_lines)

        containing = find_containing_function(hit_addr, func_list)

        call_sites.append(
            CallSite(
                address=hit_addr,
                function_name=imp.name,
                containing_function=containing,
                disassembly_lines=context,
            )
        )

    return call_sites


def _resolve_call_target(
    insn: object,
    plt_targets: dict[int, DangerousImport],
    got_targets: dict[int, DangerousImport],
) -> DangerousImport | None:
    """Resolve a call/jmp instruction to a dangerous import.

    Handles:
    - Direct calls: operand is an immediate address matching a PLT entry.
    - Indirect GOT calls: operand is [rip + offset], memory target matches
      a GOT entry for a dangerous import.

    Args:
        insn: A capstone instruction object.
        plt_targets: Map of PLT addresses to dangerous imports.
        got_targets: Map of GOT addresses to dangerous imports.

    Returns:
        The matched DangerousImport, or None.
    """
    cs_insn = insn  # type: ignore[assignment]

    # Try direct call first (most common)
    target = _parse_direct_target(cs_insn)
    if target is not None and target in plt_targets:
        return plt_targets[target]

    # Try indirect call through GOT: call qword ptr [rip + disp]
    if got_targets and hasattr(cs_insn, "operands"):
        try:
            operands = cs_insn.operands
            if len(operands) == 1:
                op = operands[0]
                if (
                    op.type == x86_const.X86_OP_MEM
                    and op.mem.base == x86_const.X86_REG_RIP
                    and op.mem.index == 0
                ):
                    # RIP-relative: target = instruction_end + displacement
                    insn_addr: int = cs_insn.address  # type: ignore[attr-defined]
                    insn_size: int = cs_insn.size  # type: ignore[attr-defined]
                    mem_target = insn_addr + insn_size + op.mem.disp
                    if mem_target in got_targets:
                        return got_targets[mem_target]
        except (AttributeError, IndexError):
            pass

    return None


def _parse_direct_target(insn: object) -> int | None:
    """Extract the immediate target address from a direct call/jmp.

    Args:
        insn: A capstone instruction object.

    Returns:
        The target address if it's an immediate operand, None otherwise.
    """
    try:
        op_str: str = insn.op_str  # type: ignore[attr-defined]
        if op_str.startswith("0x") or op_str.startswith("0X"):
            return int(op_str, 16)
        # Handle negative or decimal operands
        return int(op_str, 0)
    except (ValueError, AttributeError):
        return None


def _extract_context(
    md: Cs,
    text_data: bytes,
    text_addr: int,
    target_addr: int,
    context_lines: int,
) -> list[DisassemblyLine]:
    """Extract a disassembly context window around a target address.

    Disassembles a region around the target rather than the full .text,
    starting from an estimated offset before the target.

    Args:
        md: Capstone disassembler instance.
        text_data: Raw bytes of the .text section.
        text_addr: Virtual address of .text start.
        target_addr: The address to center the context on.
        context_lines: Number of instructions before/after.

    Returns:
        List of disassembly lines forming the context window.
    """
    # Scan a region around the target. Variable-length x86_64 instructions
    # mean starting from an arbitrary offset may mis-align, so we use a wide
    # window and retry with a larger one if the target address isn't found.
    for multiplier in (16, 32, 64):
        scan_before = context_lines * multiplier
        scan_after = context_lines * multiplier

        region_start = max(text_addr, target_addr - scan_before)
        region_end = min(text_addr + len(text_data), target_addr + scan_after)

        offset = region_start - text_addr
        length = region_end - region_start
        region_data = text_data[offset : offset + length]

        all_insns: list[tuple[int, str, str]] = []
        target_idx = -1

        for insn in md.disasm(region_data, region_start):
            all_insns.append((insn.address, insn.mnemonic, insn.op_str))
            if insn.address == target_addr:
                target_idx = len(all_insns) - 1

        if target_idx >= 0:
            break

    if target_idx < 0:
        return []

    start = max(0, target_idx - context_lines)
    end = min(len(all_insns), target_idx + context_lines + 1)

    return [
        DisassemblyLine(address=addr, mnemonic=mn, op_str=ops)
        for addr, mn, ops in all_insns[start:end]
    ]
