"""Tests for stack frame layout reconstruction."""

from elftriage.stackframe import (
    StackFrameLayout,
    StackSlot,
    estimate_distance_to_return_address,
    get_slot_for_offset,
)


def test_distance_to_return_rbp_frame() -> None:
    """For rbp-based frames, distance from [rbp-0x40] to ret is 0x48."""
    slot = StackSlot(offset=-0x40, size_estimate=32)
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
        frame_base="rbp",
        slots=[slot],
        has_frame_pointer=True,
        confidence="high",
    )
    distance = estimate_distance_to_return_address(layout, slot)
    assert distance == 0x40 + 8  # 72 bytes


def test_distance_returns_none_for_rsp_frame() -> None:
    """RSP-based frames should return None (not enough confidence)."""
    slot = StackSlot(offset=0x20, size_estimate=16)
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
        frame_base="rsp",
        slots=[slot],
        has_frame_pointer=False,
        confidence="low",
    )
    assert estimate_distance_to_return_address(layout, slot) is None


def test_distance_returns_none_for_positive_offset() -> None:
    """Positive offsets (above rbp) should return None."""
    slot = StackSlot(offset=0x10)
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
        frame_base="rbp",
        slots=[slot],
        has_frame_pointer=True,
        confidence="high",
    )
    assert estimate_distance_to_return_address(layout, slot) is None


def test_get_slot_exact_match() -> None:
    """Should find a slot with exact offset match."""
    slot = StackSlot(offset=-0x40, size_estimate=32)
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
        slots=[slot],
    )
    assert get_slot_for_offset(layout, -0x40) is slot


def test_get_slot_within_range() -> None:
    """Should find a slot when offset falls within its range."""
    slot = StackSlot(offset=-0x40, size_estimate=32)
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
        slots=[slot],
    )
    # -0x40 + 32 = -0x20, so -0x30 is within [-0x40, -0x20)
    assert get_slot_for_offset(layout, -0x30) is slot


def test_get_slot_returns_none_outside_range() -> None:
    """Should return None when offset is outside all slot ranges."""
    slot = StackSlot(offset=-0x40, size_estimate=32)
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
        slots=[slot],
    )
    assert get_slot_for_offset(layout, -0x100) is None


def test_get_slot_empty_layout() -> None:
    """Should return None for a layout with no slots."""
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
    )
    assert get_slot_for_offset(layout, -0x40) is None


def test_multiple_slots_sorted() -> None:
    """Layout with multiple slots should allow looking up each."""
    slot_a = StackSlot(offset=-0x40, size_estimate=16)
    slot_b = StackSlot(offset=-0x30, size_estimate=16)
    slot_c = StackSlot(offset=-0x20, size_estimate=16)
    layout = StackFrameLayout(
        function_name="test",
        function_start=0x1000,
        slots=[slot_a, slot_b, slot_c],
    )
    assert get_slot_for_offset(layout, -0x40) is slot_a
    assert get_slot_for_offset(layout, -0x30) is slot_b
    assert get_slot_for_offset(layout, -0x20) is slot_c
