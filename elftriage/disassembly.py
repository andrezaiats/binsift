"""Capstone-based disassembly engine for call-site context extraction."""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

from elftriage.types import CallSite, DangerousImport, DisassemblyLine


def disassemble_call_sites(
    elffile: ELFFile,
    imports: list[DangerousImport],
    context_lines: int = 5,
) -> list[CallSite]:
    """Find and disassemble call sites for dangerous imports.

    Scans the .text section for call/jmp instructions targeting PLT entries
    of dangerous functions, then extracts surrounding instruction context.

    Args:
        elffile: A parsed ELF file object.
        imports: List of dangerous imports with PLT addresses.
        context_lines: Number of instructions to show before and after the call.

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

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Pre-disassemble the entire .text section
    all_instructions = list(md.disasm(text_data, text_addr))
    if not all_instructions:
        return []

    # Build a set of PLT addresses to look for
    plt_targets: dict[int, DangerousImport] = {imp.plt_address: imp for imp in imports}

    call_sites: list[CallSite] = []

    for i, insn in enumerate(all_instructions):
        if insn.mnemonic not in ("call", "jmp"):
            continue

        # Parse the operand as an immediate address
        target = _parse_call_target(insn)
        if target is None or target not in plt_targets:
            continue

        imp = plt_targets[target]

        # Extract context window
        start = max(0, i - context_lines)
        end = min(len(all_instructions), i + context_lines + 1)
        context = all_instructions[start:end]

        lines = [
            DisassemblyLine(
                address=ctx_insn.address,
                mnemonic=ctx_insn.mnemonic,
                op_str=ctx_insn.op_str,
            )
            for ctx_insn in context
        ]

        call_sites.append(
            CallSite(
                address=insn.address,
                function_name=imp.name,
                disassembly_lines=lines,
            )
        )

    return call_sites


def _parse_call_target(insn: object) -> int | None:
    """Extract the immediate target address from a call/jmp instruction.

    Args:
        insn: A capstone instruction object.

    Returns:
        The target address if it's an immediate operand, None otherwise.
    """
    try:
        # For direct calls, the operand string is the hex address
        op_str = insn.op_str  # type: ignore[attr-defined]
        if op_str.startswith("0x") or op_str.startswith("0X"):
            return int(op_str, 16)
        # Try parsing as plain integer
        return int(op_str, 0)
    except (ValueError, AttributeError):
        return None
