"""Tests for backward-slice argument analysis."""

from elftools.elf.elffile import ELFFile

from elftriage.imports import resolve_dangerous_imports
from elftriage.disassembly import disassemble_call_sites
from elftriage.arganalysis import analyze_call_arguments
from elftriage.types import ArgSource


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
