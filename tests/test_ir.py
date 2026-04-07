"""Tests for the optional P-Code IR lifting module."""

from __future__ import annotations

import pytest
from elftools.elf.elffile import ELFFile

from elftriage.functions import detect_functions
from elftriage.ir import CAPABILITY_WARNING, IR_AVAILABLE, lift_function
from elftriage.types import FunctionBoundary


def test_capability_warning_mentions_install() -> None:
    assert "pip install" in CAPABILITY_WARNING
    assert "[ir]" in CAPABILITY_WARNING


def test_lift_function_returns_none_when_unavailable() -> None:
    if IR_AVAILABLE:
        pytest.skip("pypcode is installed; None-on-absence path is not exercised")
    boundary = FunctionBoundary(name="x", start_address=0x1000, end_address=0x1010)

    class _FakeElf:
        def get_section_by_name(self, name: str) -> None:
            return None

    assert lift_function(_FakeElf(), boundary) is None  # type: ignore[arg-type]


@pytest.mark.skipif(not IR_AVAILABLE, reason="pypcode not installed")
def test_lift_function_real_binary(bin_ls_elffile: ELFFile) -> None:
    """Lifting at least one /bin/ls function should produce non-empty ops."""
    functions = detect_functions(bin_ls_elffile)
    if not functions:
        pytest.skip("/bin/ls has no detected functions on this host")
    # Try lifting a few — at least one should succeed.
    successes = 0
    for fn in functions[:20]:
        ir = lift_function(bin_ls_elffile, fn)
        if ir is not None and ir.ops:
            successes += 1
    assert successes > 0, "expected at least one /bin/ls function to lift"
