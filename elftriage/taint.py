"""Backward reaching definitions over P-Code for argument provenance.

This module is the IR-backed replacement for the windowed slice in
:mod:`elftriage.arganalysis`. Given a lifted function and an asm-level
call address, it walks the P-Code ops in reverse to determine the
provenance of each SysV-AMD64 argument register at the moment of the
call. P-Code is much friendlier than raw x86 for this — register
aliasing between ``eax``/``rax`` is gone, every operation is explicit,
and stack arithmetic is reduced to ``RBP + const``.

It also detects pointer-escape: whether the address of a stack slot
identified as a destination buffer was passed to *another* call before
or after the target call. That single signal is what lets the
classifier promote ``dest_is_stack`` to ``CONFIRMED`` honestly — without
it the slot may be aliased somewhere outside the current function.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from elftriage.ir import FunctionIR
from elftriage.types import ArgSource


# Register varnode offsets in pypcode's x86:LE:64:default sleigh spec.
# Verified empirically; pypcode exposes these via Context.getRegisterName
# but using literal offsets is faster and unambiguous.
_REG_RAX = 0x00
_REG_RCX = 0x08
_REG_RDX = 0x10
_REG_RBX = 0x18
_REG_RSP = 0x20
_REG_RBP = 0x28
_REG_RSI = 0x30
_REG_RDI = 0x38
_REG_R8 = 0x80
_REG_R9 = 0x88

_ARG_REG_OFFSETS: dict[str, int] = {
    "rdi": _REG_RDI,
    "rsi": _REG_RSI,
    "rdx": _REG_RDX,
    "rcx": _REG_RCX,
    "r8": _REG_R8,
    "r9": _REG_R9,
}

_STACK_REG_OFFSETS = {_REG_RBP, _REG_RSP}

# Maximum recursive trace depth through unique/temporary varnodes
# before we give up and return UNKNOWN. P-Code expansions tend to be
# shallow (3–6 ops per asm instruction), so 32 is comfortably enough.
_MAX_TRACE_DEPTH = 32


@dataclass
class TaintInfo:
    """Provenance of a single register at a call site."""

    source: ArgSource = ArgSource.UNKNOWN
    detail: str = ""
    # Constant value when the source is a literal/immediate, or the
    # offset relative to RBP/RSP when the source is a stack address.
    constant: Optional[int] = None
    stack_offset: Optional[int] = None


@dataclass
class CallTaint:
    """Result of taint analysis at a single call site.

    Attributes:
        args: Mapping from argument register name (lowercase) to its
            :class:`TaintInfo`.
        stack_dest_escapes: True if the destination's stack slot
            address can be observed escaping to another call within
            the same function. ``None`` when there is no stack
            destination at all.
    """

    args: dict[str, TaintInfo]
    stack_dest_escapes: Optional[bool] = None


def taint_at_call(
    function_ir: FunctionIR,
    call_address: int,
    arg_registers: list[str],
) -> Optional[CallTaint]:
    """Compute argument provenance at *call_address* within *function_ir*.

    Walks ``function_ir.ops`` to find the IMARK matching the call
    instruction, then runs a backward reach for each named argument
    register. Also performs an escape check on any stack-derived
    destination (``rdi``).

    Returns ``None`` if the call address is not represented in the
    lifted ops (e.g. the call is outside the function bounds).

    Args:
        function_ir: Lifted P-Code for the containing function.
        call_address: Asm-level address of the ``call`` instruction.
        arg_registers: Lowercase ABI registers to trace, in order
            (typically a prefix of ``["rdi", "rsi", "rdx", "rcx",
            "r8", "r9"]``).

    Returns:
        A :class:`CallTaint`, or ``None`` if the call address is not
        in the lifted function.
    """
    ops = function_ir.ops
    call_idx = _find_call_op_index(ops, call_address)
    if call_idx is None:
        return None

    pre_ops = ops[:call_idx]

    args: dict[str, TaintInfo] = {}
    for reg in arg_registers:
        offset = _ARG_REG_OFFSETS.get(reg)
        if offset is None:
            args[reg] = TaintInfo(
                source=ArgSource.UNKNOWN, detail="unsupported register"
            )
            continue
        args[reg] = _trace_register(pre_ops, offset, depth=0)

    # Escape check: scan all CALL ops other than the target and see
    # whether any of them gets the same stack slot in any of its arg
    # registers.
    rdi_info = args.get("rdi")
    escapes: Optional[bool] = None
    if (
        rdi_info
        and rdi_info.source == ArgSource.STACK
        and rdi_info.stack_offset is not None
    ):
        escapes = _stack_slot_escapes(ops, call_idx, rdi_info.stack_offset)

    return CallTaint(args=args, stack_dest_escapes=escapes)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _find_call_op_index(ops: list[object], call_address: int) -> Optional[int]:
    """Locate the index of the CALL/CALLIND op for *call_address*.

    The lifter emits an IMARK op at the start of each asm instruction
    with ``inputs[0]`` being a ``ram[addr:size]`` varnode. We find the
    IMARK whose ram offset matches and then walk forward to its CALL
    op (which sits a few ops later within the same instruction).
    """
    in_target_instr = False
    for i, op in enumerate(ops):
        opcode_name = op.opcode.name  # type: ignore[attr-defined]
        if opcode_name == "IMARK":
            inp0 = op.inputs[0]  # type: ignore[attr-defined]
            in_target_instr = inp0.space.name == "ram" and inp0.offset == call_address
            continue
        if in_target_instr and opcode_name in ("CALL", "CALLIND"):
            return i
    return None


def _trace_register(ops: list[object], reg_offset: int, depth: int) -> TaintInfo:
    """Backward-reach a single register varnode through pre-call ops."""
    return _trace_varnode(ops, "register", reg_offset, depth)


def _trace_varnode(ops: list[object], space: str, offset: int, depth: int) -> TaintInfo:
    """Find the latest write to a varnode and classify its source.

    Walks ``ops`` from the end backwards looking for the most recent
    op whose ``output`` matches ``(space, offset)``. When recursing
    through that op's inputs, the ``ops`` list is truncated to the
    prefix up to the matched op so that subsequent traces only see
    writes that *predate* the current one. This is essential for
    correctness in patterns like::

        lea rax, [rbp-0x10]   ; rax = stack address
        mov rdi, rax          ; rdi = rax
        mov eax, 0            ; rax overwritten with 0
        call gets             ; rdi is still the stack address

    Without the prefix truncation, tracing RDI → RAX would walk all
    the way to ``mov eax, 0`` and falsely report rdi as the constant
    zero. With truncation, the trace of RAX is bounded to the prefix
    ending at ``mov rdi, rax`` and correctly finds ``lea rax``.

    Args:
        ops: Pre-call P-Code ops in original execution order.
        space: Varnode space name (``"register"``, ``"unique"``, ...).
        offset: Varnode offset within that space.
        depth: Current recursion depth (for cycle protection).

    Returns:
        A :class:`TaintInfo` describing what flowed into the varnode.
    """
    if depth > _MAX_TRACE_DEPTH:
        return TaintInfo(source=ArgSource.UNKNOWN, detail="trace depth exceeded")

    for i in range(len(ops) - 1, -1, -1):
        op = ops[i]
        out = op.output  # type: ignore[attr-defined]
        if out is None:
            continue
        if out.space.name != space or out.offset != offset:
            continue

        opcode_name = op.opcode.name  # type: ignore[attr-defined]
        inputs = list(op.inputs)  # type: ignore[attr-defined]
        # Recursive traces must only see writes that predate this op.
        return _classify_op(opcode_name, inputs, ops[:i], depth)

    return TaintInfo(source=ArgSource.UNKNOWN, detail="no defining write found")


def _classify_op(
    opcode_name: str,
    inputs: list[object],
    ops: list[object],
    depth: int,
) -> TaintInfo:
    """Classify the source of a P-Code op that writes our target varnode."""

    if opcode_name == "COPY":
        src = inputs[0]
        return _classify_source_varnode(src, ops, depth + 1)

    if opcode_name in ("INT_ADD", "INT_SUB"):
        # Stack-pointer arithmetic: RBP/RSP + const → stack slot.
        return _classify_stack_arith(opcode_name, inputs, ops, depth + 1)

    if opcode_name == "LOAD":
        # LOAD inputs: (space_id_const, address_varnode)
        if len(inputs) >= 2:
            addr = inputs[1]
            inner = _classify_source_varnode(addr, ops, depth + 1)
            if inner.source == ArgSource.STACK:
                return TaintInfo(
                    source=ArgSource.STACK,
                    detail="loaded from stack: " + (inner.detail or ""),
                    stack_offset=inner.stack_offset,
                )
        return TaintInfo(source=ArgSource.UNKNOWN, detail="memory load")

    if opcode_name in ("CALL", "CALLIND"):
        return TaintInfo(source=ArgSource.UNKNOWN, detail="call result")

    return TaintInfo(source=ArgSource.UNKNOWN, detail=f"op {opcode_name}")


def _classify_source_varnode(
    varnode: object, ops: list[object], depth: int
) -> TaintInfo:
    """Classify a varnode as a source operand."""
    space = varnode.space.name  # type: ignore[attr-defined]
    offset = varnode.offset  # type: ignore[attr-defined]

    if space == "const":
        return TaintInfo(
            source=ArgSource.UNKNOWN,
            detail=f"immediate 0x{offset:x}",
            constant=offset,
        )

    if space == "register":
        if offset in _STACK_REG_OFFSETS:
            return TaintInfo(
                source=ArgSource.STACK,
                detail="bare stack register",
                stack_offset=0,
            )
        # Trace the register backward.
        return _trace_varnode(ops, "register", offset, depth)

    if space == "unique":
        return _trace_varnode(ops, "unique", offset, depth)

    return TaintInfo(source=ArgSource.UNKNOWN, detail=f"{space}[{offset:x}]")


def _classify_stack_arith(
    opcode_name: str,
    inputs: list[object],
    ops: list[object],
    depth: int,
) -> TaintInfo:
    """Recognize ``RBP/RSP +/- const`` patterns as stack-relative addresses."""
    if len(inputs) < 2:
        return TaintInfo(source=ArgSource.UNKNOWN, detail=opcode_name)

    a, b = inputs[0], inputs[1]
    a_space = a.space.name  # type: ignore[attr-defined]
    b_space = b.space.name  # type: ignore[attr-defined]
    a_off = a.offset  # type: ignore[attr-defined]
    b_off = b.offset  # type: ignore[attr-defined]

    base_offset: Optional[int] = None
    const_value: Optional[int] = None
    base_name = ""

    if a_space == "register" and a_off in _STACK_REG_OFFSETS and b_space == "const":
        base_offset = a_off
        const_value = b_off
        base_name = "rbp" if a_off == _REG_RBP else "rsp"
    elif b_space == "register" and b_off in _STACK_REG_OFFSETS and a_space == "const":
        base_offset = b_off
        const_value = a_off
        base_name = "rbp" if b_off == _REG_RBP else "rsp"

    if base_offset is None or const_value is None:
        # Could be propagating through a non-stack add — fall back to
        # tracing the non-const operand once.
        for inp in inputs:
            if inp.space.name != "const":  # type: ignore[attr-defined]
                return _classify_source_varnode(inp, ops, depth + 1)
        return TaintInfo(source=ArgSource.UNKNOWN, detail=opcode_name)

    # Convert unsigned const to a signed offset.
    if const_value & (1 << 63):
        signed = const_value - (1 << 64)
    else:
        signed = const_value
    if opcode_name == "INT_SUB":
        signed = -signed
    return TaintInfo(
        source=ArgSource.STACK,
        detail=f"{base_name}{signed:+d}",
        stack_offset=signed,
    )


def _stack_slot_escapes(
    ops: list[object], target_call_idx: int, slot_offset: int
) -> bool:
    """Detect whether *slot_offset* is passed to any other CALL.

    Scans every CALL op in the function (except the target call) and
    checks whether RDI/RSI/RDX/RCX/R8/R9 at that point trace back to
    the same RBP-relative slot. A single match means the slot escapes.
    """
    for i, op in enumerate(ops):
        if i == target_call_idx:
            continue
        opcode_name = op.opcode.name  # type: ignore[attr-defined]
        if opcode_name not in ("CALL", "CALLIND"):
            continue

        pre_ops = ops[:i]
        for reg_offset in _ARG_REG_OFFSETS.values():
            info = _trace_varnode(pre_ops, "register", reg_offset, depth=0)
            if info.source == ArgSource.STACK and info.stack_offset == slot_offset:
                return True
    return False
