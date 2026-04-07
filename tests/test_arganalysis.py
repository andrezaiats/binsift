"""Tests for backward-slice argument analysis."""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

from elftriage.imports import resolve_dangerous_imports
from elftriage.disassembly import disassemble_call_sites
from elftriage.arganalysis import analyze_call_arguments, _extract_copy_size
from elftriage.types import ArgSource


def _disasm(code: bytes, base: int = 0x1000) -> list[object]:
    """Helper: disassemble a small byte string into capstone instructions."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    return list(md.disasm(code, base))


def test_analyze_populates_arguments(bin_ls_elffile: ELFFile) -> None:
    """Argument analysis should populate at least some call site arguments."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    call_sites = disassemble_call_sites(bin_ls_elffile, imports, context_lines=5)
    analyzed = analyze_call_arguments(bin_ls_elffile, call_sites)

    has_args = any(len(site.arguments) > 0 for site in analyzed)
    assert has_args, "At least some call sites should have arguments analyzed"


def test_argument_sources_are_valid(bin_ls_elffile: ELFFile) -> None:
    """All argument sources should be valid ArgSource values."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    call_sites = disassemble_call_sites(bin_ls_elffile, imports, context_lines=5)
    analyzed = analyze_call_arguments(bin_ls_elffile, call_sites)

    valid_sources = set(ArgSource)
    for site in analyzed:
        for arg in site.arguments:
            assert arg.source in valid_sources
            assert arg.register in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


def test_empty_call_sites_returns_empty(bin_ls_elffile: ELFFile) -> None:
    """Empty call sites list should return empty."""
    result = analyze_call_arguments(bin_ls_elffile, [])
    assert result == []


def test_stack_source_detection(bin_ls_elffile: ELFFile) -> None:
    """At least some arguments should be classified as stack sources."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    call_sites = disassemble_call_sites(bin_ls_elffile, imports, context_lines=5)
    analyzed = analyze_call_arguments(bin_ls_elffile, call_sites)

    has_stack = any(
        arg.source == ArgSource.STACK for site in analyzed for arg in site.arguments
    )
    # /bin/ls uses stack buffers — this should find at least one
    assert has_stack, "Should detect at least one stack-sourced argument"


def test_argument_detail_not_empty(bin_ls_elffile: ELFFile) -> None:
    """Arguments with known sources should have detail strings."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    call_sites = disassemble_call_sites(bin_ls_elffile, imports, context_lines=5)
    analyzed = analyze_call_arguments(bin_ls_elffile, call_sites)

    for site in analyzed:
        for arg in site.arguments:
            if arg.source != ArgSource.UNKNOWN:
                assert arg.detail, f"Arg {arg.register} has source but no detail"


# ---------------------------------------------------------------------------
# copy_size extraction
# ---------------------------------------------------------------------------


def test_extract_copy_size_immediate_rdx_for_memcpy() -> None:
    """A literal `mov rdx, 0x100` immediately before a memcpy gives copy_size."""
    # mov rdx, 0x100 ; mov rsi, rax ; mov rdi, rbx
    code = b"\x48\xc7\xc2\x00\x01\x00\x00" + b"\x48\x89\xc6" + b"\x48\x89\xd9"
    insns = _disasm(code)
    assert _extract_copy_size(insns, "memcpy") == 0x100


def test_extract_copy_size_immediate_rsi_for_fgets() -> None:
    """A literal `mov rsi, 0x40` immediately before fgets gives copy_size."""
    # mov rsi, 0x40 ; mov rdi, rax
    code = b"\x48\xc7\xc6\x40\x00\x00\x00" + b"\x48\x89\xc7"
    insns = _disasm(code)
    assert _extract_copy_size(insns, "fgets") == 0x40


def test_extract_copy_size_register_returns_none() -> None:
    """A register-to-register copy of the size argument is not derivable."""
    # mov rdx, rbx ; mov rsi, rax
    code = b"\x48\x89\xda" + b"\x48\x89\xc6"
    insns = _disasm(code)
    assert _extract_copy_size(insns, "memcpy") is None


def test_extract_copy_size_memory_load_returns_none() -> None:
    """A memory load into the size register is not a constant size."""
    # mov rdx, qword ptr [rbp - 0x10]
    code = b"\x48\x8b\x55\xf0"
    insns = _disasm(code)
    assert _extract_copy_size(insns, "memcpy") is None


def test_extract_copy_size_unknown_function_returns_none() -> None:
    """Functions without a known size argument are not analyzed."""
    code = b"\x48\xc7\xc2\x00\x01\x00\x00"
    insns = _disasm(code)
    assert _extract_copy_size(insns, "strcpy") is None
    assert _extract_copy_size(insns, "gets") is None
