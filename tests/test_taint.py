"""Tests for the optional P-Code taint backend."""

from __future__ import annotations

import pytest

from elftriage.ir import IR_AVAILABLE, FunctionIR
from elftriage.types import ArgSource

if IR_AVAILABLE:
    import pypcode  # noqa: F401  (only needed for the live tests)
    from elftriage.taint import taint_at_call

pytestmark = pytest.mark.skipif(
    not IR_AVAILABLE, reason="pypcode not installed; IR taint tests skipped"
)


def _lift(code: bytes, base: int = 0x1000) -> FunctionIR:
    """Translate *code* into a synthetic FunctionIR for testing."""
    ctx = pypcode.Context("x86:LE:64:default")  # type: ignore[name-defined]
    tx = ctx.translate(code, base, 0, len(code))
    return FunctionIR(function_name="test", function_start=base, ops=list(tx.ops))


def test_taint_resolves_lea_through_register_alias() -> None:
    """The slice misses ``lea rax + mov rdi, rax``; IR should resolve it."""
    # 0x1000: lea rax, [rbp - 0x40]
    # 0x1004: mov rdi, rax
    # 0x1007: call _ (rel -1, 5-byte call)
    code = b"\x48\x8d\x45\xc0" + b"\x48\x89\xc7" + b"\xe8\xff\xff\xff\xff"
    ir = _lift(code)
    result = taint_at_call(ir, 0x1007, ["rdi"])
    assert result is not None
    info = result.args["rdi"]
    assert info.source == ArgSource.STACK
    assert info.stack_offset == -64


def test_taint_respects_temporal_order_of_writes() -> None:
    """A later write to a different register must not poison earlier reads.

    The compiler often emits ``mov eax, 0`` between an ``lea`` that
    sets up an argument register and the call that consumes it. The
    backward trace must walk through ``mov rdi, rax`` and find the
    ``lea`` that came *before* the ``mov rdi, rax`` — not the later
    ``mov eax, 0`` that overwrote rax after the alias was made.
    """
    # 0x1000: lea rax, [rbp - 0x10]
    # 0x1004: mov rdi, rax
    # 0x1007: mov eax, 0
    # 0x100c: call _ (5-byte)
    code = (
        b"\x48\x8d\x45\xf0"
        + b"\x48\x89\xc7"
        + b"\xb8\x00\x00\x00\x00"
        + b"\xe8\xff\xff\xff\xff"
    )
    ir = _lift(code)
    result = taint_at_call(ir, 0x100C, ["rdi"])
    assert result is not None
    info = result.args["rdi"]
    assert info.source == ArgSource.STACK, info.detail
    assert info.stack_offset == -16


def test_taint_extracts_constant_immediate_from_rsi() -> None:
    """An ``mov rsi, imm`` is exposed via TaintInfo.constant."""
    # 0x1000: mov rsi, 0x100
    # 0x1007: call _ (5-byte)
    code = b"\x48\xc7\xc6\x00\x01\x00\x00" + b"\xe8\xff\xff\xff\xff"
    ir = _lift(code)
    result = taint_at_call(ir, 0x1007, ["rsi"])
    assert result is not None
    info = result.args["rsi"]
    assert info.constant == 0x100


def test_taint_no_escape_when_slot_only_used_once() -> None:
    """A stack slot used in exactly one call has escapes=False."""
    # 0x1000: lea rdi, [rbp - 0x40]
    # 0x1004: call _ (5-byte)
    code = b"\x48\x8d\x7d\xc0" + b"\xe8\xff\xff\xff\xff"
    ir = _lift(code)
    result = taint_at_call(ir, 0x1004, ["rdi"])
    assert result is not None
    assert result.stack_dest_escapes is False


def test_taint_escape_when_slot_passed_to_another_call() -> None:
    """If the same slot reaches a second call, escape detection fires."""
    # 0x1000: lea rdi, [rbp - 0x40]
    # 0x1004: call _   (target)
    # 0x1009: lea rdi, [rbp - 0x40]
    # 0x100d: call _   (later)
    code = (
        b"\x48\x8d\x7d\xc0"
        + b"\xe8\xff\xff\xff\xff"
        + b"\x48\x8d\x7d\xc0"
        + b"\xe8\xff\xff\xff\xff"
    )
    ir = _lift(code)
    result = taint_at_call(ir, 0x1004, ["rdi"])
    assert result is not None
    assert result.stack_dest_escapes is True


def test_taint_returns_none_for_unknown_call_address() -> None:
    """Asking about an address not in the lifted ops returns None."""
    code = b"\x48\x8d\x7d\xc0" + b"\xe8\xff\xff\xff\xff"
    ir = _lift(code)
    assert taint_at_call(ir, 0xDEAD, ["rdi"]) is None


def test_taint_returns_none_when_no_call_op() -> None:
    """A function with no call instructions returns None."""
    # nop; nop; nop
    code = b"\x90\x90\x90"
    ir = _lift(code)
    assert taint_at_call(ir, 0x1000, ["rdi"]) is None
