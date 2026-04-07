"""Optional P-Code IR lifting via pypcode.

Wraps the third-party ``pypcode`` package, which exposes Ghidra's
SLEIGH-based P-Code translator. P-Code is a small, regular IR where
every instruction is decomposed into explicit operations on typed
varnodes — far more tractable than raw x86 for backward reaching
definitions.

This module is opt-in. ``IR_AVAILABLE`` is ``True`` only when
``pypcode`` is importable; callers fall back to the existing slice
backend in :mod:`elftriage.arganalysis` otherwise. The capability gap
is surfaced via the per-finding marker that the classifier adds when a
finding's arguments came from the slice path while pypcode was absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from elftools.elf.elffile import ELFFile

from elftriage.types import FunctionBoundary

try:
    import pypcode  # type: ignore[import-not-found]

    IR_AVAILABLE: bool = True
except ImportError:
    pypcode = None  # type: ignore[assignment]
    IR_AVAILABLE = False


CAPABILITY_WARNING = (
    "IR-based taint analysis unavailable: install with "
    "'pip install -e .[ir]' (argument provenance falls back to a "
    "15-instruction backward slice and may miss aliasing or reordering)"
)


@dataclass
class FunctionIR:
    """Lifted P-Code for a single function.

    Attributes:
        function_name: Name of the lifted function.
        function_start: Start address of the function in the binary.
        ops: Flat list of P-Code operations in execution order. The
            list interleaves IMARK ops (one per source instruction)
            with the operations they expand into.
    """

    function_name: str
    function_start: int
    ops: list[object] = field(default_factory=list)


def lift_function(elffile: ELFFile, function: FunctionBoundary) -> Optional[FunctionIR]:
    """Lift the body of a function to a flat list of P-Code ops.

    Returns ``None`` if pypcode is unavailable, if the .text section
    cannot be found, or if the function bounds fall outside .text.
    Errors during translation are caught and degrade to ``None``.

    Args:
        elffile: A parsed ELF file object.
        function: Function boundary describing the byte range to lift.

    Returns:
        A populated :class:`FunctionIR`, or ``None`` on any failure.
    """
    if not IR_AVAILABLE:
        return None

    text_section = elffile.get_section_by_name(".text")
    if text_section is None:
        return None

    text_data = text_section.data()
    text_addr: int = text_section.header.sh_addr
    text_end = text_addr + len(text_data)

    func_start = max(function.start_address, text_addr)
    func_end = min(function.end_address, text_end)
    if func_start >= func_end:
        return None

    offset_in_section = func_start - text_addr
    func_data = text_data[
        offset_in_section : offset_in_section + (func_end - func_start)
    ]
    if not func_data:
        return None

    try:
        ctx = pypcode.Context("x86:LE:64:default")
        translation = ctx.translate(func_data, func_start, 0, len(func_data))
    except Exception:
        return None

    return FunctionIR(
        function_name=function.name,
        function_start=func_start,
        ops=list(translation.ops),
    )
