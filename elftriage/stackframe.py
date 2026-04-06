"""Stack frame layout reconstruction from disassembly.

Scans all instructions within a function to find every reference to the
stack (rbp-relative and rsp-relative), builds a map of stack slots, and
computes distances between adjacent slots. This provides context for
buffer-overflow triage by identifying stack variable sizes and layout.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

from elftriage.types import FunctionBoundary


@dataclass
class StackSlot:
    """A detected stack slot (variable or buffer).

    Attributes:
        offset: Offset from frame base (negative = below rbp).
        size_estimate: Distance to next slot, 0 if unknown.
        access_type: How the slot is accessed: "lea" (address taken,
            likely buffer), "mov" (read/write), or "both".
        references: How many instructions reference this slot.
        confidence: "confirmed" if clear rbp/rsp pattern,
            "inferred" otherwise.
    """

    offset: int
    size_estimate: int = 0
    access_type: str = "mov"
    references: int = 0
    confidence: str = "confirmed"


@dataclass
class StackFrameLayout:
    """Reconstructed stack frame layout for a function.

    Attributes:
        function_name: Name of the analyzed function.
        function_start: Start address of the function.
        frame_base: Register used as frame base: "rbp", "rsp", or "unknown".
        slots: List of detected stack slots, sorted by offset.
        total_frame_size: Frame size from ``sub rsp, N`` or distance from
            rbp to the lowest slot.
        has_frame_pointer: Whether the function uses an rbp frame pointer.
        confidence: "high" if frame pointer present, "low" if rsp-only.
    """

    function_name: str
    function_start: int
    frame_base: str = "unknown"
    slots: list[StackSlot] = field(default_factory=list)
    total_frame_size: int = 0
    has_frame_pointer: bool = False
    confidence: str = "low"


def analyze_stack_frame(
    elffile: ELFFile,
    function: FunctionBoundary,
) -> StackFrameLayout:
    """Reconstruct the stack frame layout for a single function.

    Disassembles the function body, detects frame-pointer usage, collects
    all stack-relative memory references, and estimates slot sizes from
    the distance between adjacent offsets.

    Args:
        elffile: A parsed ELF file object.
        function: The function boundary to analyze.

    Returns:
        A ``StackFrameLayout`` describing the detected stack slots.
    """
    layout = StackFrameLayout(
        function_name=function.name,
        function_start=function.start_address,
    )

    func_size = function.end_address - function.start_address
    if func_size <= 0:
        return layout

    text_section = elffile.get_section_by_name(".text")
    if text_section is None:
        return layout

    text_data = text_section.data()
    text_addr: int = text_section.header.sh_addr
    text_end = text_addr + len(text_data)

    # Clamp function bounds to the .text section
    func_start = max(function.start_address, text_addr)
    func_end = min(function.end_address, text_end)
    if func_start >= func_end:
        return layout

    offset_in_section = func_start - text_addr
    func_data = text_data[
        offset_in_section : offset_in_section + (func_end - func_start)
    ]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    instructions = list(md.disasm(func_data, func_start))
    if not instructions:
        return layout

    # Step 1: detect frame pointer prologue (push rbp; mov rbp, rsp)
    has_fp = _detect_frame_pointer(instructions)
    layout.has_frame_pointer = has_fp

    if has_fp:
        layout.frame_base = "rbp"
        layout.confidence = "high"
    else:
        layout.frame_base = "rsp"
        layout.confidence = "low"

    # Step 2: find frame size from sub rsp, N
    layout.total_frame_size = _detect_frame_size(instructions)

    # Step 3: collect all stack slot references
    slot_map: dict[int, StackSlot] = {}

    for insn in instructions:
        mnemonic: str = insn.mnemonic  # type: ignore[attr-defined]
        op_str: str = insn.op_str  # type: ignore[attr-defined]

        if has_fp:
            _collect_rbp_references(mnemonic, op_str, slot_map)
        else:
            _collect_rsp_references(mnemonic, op_str, slot_map)

    if not slot_map:
        return layout

    # Step 4: sort slots by offset and compute size estimates
    sorted_offsets = sorted(slot_map.keys())
    slots: list[StackSlot] = []

    for i, off in enumerate(sorted_offsets):
        slot = slot_map[off]
        if i + 1 < len(sorted_offsets):
            slot.size_estimate = sorted_offsets[i + 1] - off
        else:
            # Last slot: try to estimate from frame size
            if has_fp and layout.total_frame_size > 0:
                # Lowest slot extends to the frame pointer area
                # For rbp-based frames with negative offsets, the lowest
                # offset is the most negative.  The slot extends up to 0
                # (rbp itself).
                if off < 0:
                    slot.size_estimate = -off
                else:
                    slot.size_estimate = 0
                    slot.confidence = "inferred"
            else:
                slot.size_estimate = 0
                slot.confidence = "inferred"
        slots.append(slot)

    layout.slots = slots

    # If frame size not detected from sub rsp, estimate from slot range
    if layout.total_frame_size == 0 and has_fp and sorted_offsets:
        lowest = sorted_offsets[0]
        if lowest < 0:
            layout.total_frame_size = abs(lowest)

    return layout


def get_slot_for_offset(
    layout: StackFrameLayout,
    offset: int,
) -> StackSlot | None:
    """Look up the stack slot that corresponds to a given offset.

    Finds the slot whose offset range contains the requested offset.
    A slot at ``slot.offset`` covers ``[slot.offset, slot.offset + size_estimate)``.

    Args:
        layout: The reconstructed stack frame layout.
        offset: The offset from the frame base to look up.

    Returns:
        The matching ``StackSlot``, or ``None`` if no slot covers the offset.
    """
    for slot in layout.slots:
        if slot.offset == offset:
            return slot
        # Check if offset falls within this slot's range
        if slot.size_estimate > 0:
            slot_end = slot.offset + slot.size_estimate
            if slot.offset <= offset < slot_end:
                return slot
    return None


def estimate_distance_to_return_address(
    layout: StackFrameLayout,
    slot: StackSlot,
) -> int | None:
    """Estimate the byte distance from a stack slot to the return address.

    For rbp-based frames, the saved return address is at ``[rbp + 8]``.
    A slot at ``[rbp - N]`` is therefore ``N + 8`` bytes from the return
    address.

    Args:
        layout: The stack frame layout (must be rbp-based).
        slot: The stack slot to measure from.

    Returns:
        The distance in bytes, or ``None`` if the frame layout does not
        provide enough confidence to compute this.
    """
    if layout.frame_base != "rbp":
        return None
    if layout.confidence != "high":
        return None
    if slot.offset >= 0:
        # Slot is at or above rbp — unusual for local variables
        return None

    # Return address is at rbp + 8, slot is at rbp + offset (offset < 0)
    # Distance = (rbp + 8) - (rbp + offset) = 8 - offset = 8 + abs(offset)
    return 8 + abs(slot.offset)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _detect_frame_pointer(instructions: list[object]) -> bool:
    """Detect whether a function uses an rbp frame pointer.

    Looks for the prologue pattern ``push rbp`` followed by
    ``mov rbp, rsp`` within the first few instructions, optionally
    preceded by ``endbr64``.

    Args:
        instructions: Disassembled instructions for the function.

    Returns:
        True if a frame-pointer prologue was detected.
    """
    # Check the first 5 instructions for the prologue pattern
    limit = min(len(instructions), 5)
    found_push_rbp = False

    for i in range(limit):
        mnemonic: str = instructions[i].mnemonic  # type: ignore[attr-defined]
        op_str: str = instructions[i].op_str  # type: ignore[attr-defined]

        if mnemonic == "push" and op_str.strip().lower() == "rbp":
            found_push_rbp = True
            continue

        if found_push_rbp and mnemonic == "mov":
            parts = [p.strip().lower() for p in op_str.split(",")]
            if len(parts) == 2 and parts[0] == "rbp" and parts[1] == "rsp":
                return True

    return False


def _detect_frame_size(instructions: list[object]) -> int:
    """Detect the stack frame size from a ``sub rsp, N`` instruction.

    Scans the first instructions of the function for the stack
    allocation.

    Args:
        instructions: Disassembled instructions for the function.

    Returns:
        The frame size in bytes, or 0 if not detected.
    """
    # sub rsp, N typically appears within the first ~10 instructions
    limit = min(len(instructions), 10)

    for i in range(limit):
        mnemonic: str = instructions[i].mnemonic  # type: ignore[attr-defined]
        op_str: str = instructions[i].op_str  # type: ignore[attr-defined]

        if mnemonic == "sub":
            parts = [p.strip().lower() for p in op_str.split(",")]
            if len(parts) == 2 and parts[0] == "rsp":
                try:
                    return int(parts[1], 0)
                except ValueError:
                    pass
    return 0


def _collect_rbp_references(
    mnemonic: str,
    op_str: str,
    slot_map: dict[int, StackSlot],
) -> None:
    """Collect stack slot references using rbp-relative addressing.

    Parses operands for patterns like ``[rbp - 0x40]`` or
    ``[rbp + 0x10]`` and records them in *slot_map*.

    Args:
        mnemonic: The instruction mnemonic.
        op_str: The operand string.
        slot_map: Mapping from offset to StackSlot (modified in place).
    """
    op_lower = op_str.lower()
    if "rbp" not in op_lower:
        return
    if "[" not in op_lower:
        return

    offsets = _extract_rbp_offsets(op_lower)
    is_lea = mnemonic.lower() == "lea"

    for off in offsets:
        _record_slot(slot_map, off, is_lea, "confirmed")


def _collect_rsp_references(
    mnemonic: str,
    op_str: str,
    slot_map: dict[int, StackSlot],
) -> None:
    """Collect stack slot references using rsp-relative addressing.

    Parses operands for patterns like ``[rsp + 0x20]`` and records
    them in *slot_map*.

    Args:
        mnemonic: The instruction mnemonic.
        op_str: The operand string.
        slot_map: Mapping from offset to StackSlot (modified in place).
    """
    op_lower = op_str.lower()
    if "rsp" not in op_lower:
        return
    if "[" not in op_lower:
        return

    offsets = _extract_rsp_offsets(op_lower)
    is_lea = mnemonic.lower() == "lea"

    for off in offsets:
        _record_slot(slot_map, off, is_lea, "confirmed")


def _record_slot(
    slot_map: dict[int, StackSlot],
    offset: int,
    is_lea: bool,
    confidence: str,
) -> None:
    """Record or update a stack slot reference.

    Args:
        slot_map: Mapping from offset to StackSlot (modified in place).
        offset: The stack offset.
        is_lea: Whether this reference is from a LEA instruction.
        confidence: Confidence level for this reference.
    """
    if offset in slot_map:
        slot = slot_map[offset]
        slot.references += 1
        if is_lea and slot.access_type == "mov":
            slot.access_type = "both"
        elif not is_lea and slot.access_type == "lea":
            slot.access_type = "both"
    else:
        slot_map[offset] = StackSlot(
            offset=offset,
            access_type="lea" if is_lea else "mov",
            references=1,
            confidence=confidence,
        )


def _extract_rbp_offsets(op_str: str) -> list[int]:
    """Extract rbp-relative offsets from an operand string.

    Handles patterns such as ``[rbp - 0x40]``, ``[rbp + 0x10]``,
    and ``[rbp - 0x40]`` embedded within size-prefixed operands
    like ``dword ptr [rbp - 0x40]``.

    Args:
        op_str: Lowercased operand string.

    Returns:
        List of integer offsets found (may be empty).
    """
    results: list[int] = []

    # Find all bracketed expressions containing rbp
    start = 0
    while True:
        bracket_start = op_str.find("[", start)
        if bracket_start == -1:
            break
        bracket_end = op_str.find("]", bracket_start)
        if bracket_end == -1:
            break

        expr = op_str[bracket_start + 1 : bracket_end].strip()
        start = bracket_end + 1

        if "rbp" not in expr:
            continue

        offset = _parse_base_plus_offset(expr, "rbp")
        if offset is not None:
            results.append(offset)

    return results


def _extract_rsp_offsets(op_str: str) -> list[int]:
    """Extract rsp-relative offsets from an operand string.

    Handles patterns such as ``[rsp + 0x20]`` and ``[rsp]``.

    Args:
        op_str: Lowercased operand string.

    Returns:
        List of integer offsets found (may be empty).
    """
    results: list[int] = []

    start = 0
    while True:
        bracket_start = op_str.find("[", start)
        if bracket_start == -1:
            break
        bracket_end = op_str.find("]", bracket_start)
        if bracket_end == -1:
            break

        expr = op_str[bracket_start + 1 : bracket_end].strip()
        start = bracket_end + 1

        if "rsp" not in expr:
            continue

        offset = _parse_base_plus_offset(expr, "rsp")
        if offset is not None:
            results.append(offset)

    return results


def _parse_base_plus_offset(expr: str, base_reg: str) -> int | None:
    """Parse ``base_reg [+-] offset`` from a bracket expression.

    Supports hex (``0x...``) and decimal offsets, as well as bare
    ``base_reg`` (offset 0).  Ignores expressions with additional
    registers (e.g. ``rbp + rax*4``).

    Args:
        expr: The content inside square brackets, lowercased.
        base_reg: The base register name ("rbp" or "rsp").

    Returns:
        The signed integer offset, or ``None`` if unparsable.
    """
    expr = expr.strip()

    # Bare register: [rbp] or [rsp]
    if expr == base_reg:
        return 0

    # Look for + or - after the base register
    reg_idx = expr.find(base_reg)
    if reg_idx == -1:
        return None

    rest = expr[reg_idx + len(base_reg) :].strip()
    if not rest:
        return 0

    # Reject complex expressions with extra registers (e.g. rbp + rax*4)
    # Allow only +/- followed by a number
    if rest[0] == "+":
        sign = 1
        num_str = rest[1:].strip()
    elif rest[0] == "-":
        sign = -1
        num_str = rest[1:].strip()
    else:
        return None

    # Reject if the remaining part contains another register name
    _REGS = {
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rsp",
        "rbp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "esp",
        "ebp",
    }
    for token in num_str.replace("*", " ").split():
        if token in _REGS:
            return None

    try:
        return sign * int(num_str, 0)
    except ValueError:
        return None
