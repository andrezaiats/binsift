"""Tests for capstone disassembly engine."""

from elftools.elf.elffile import ELFFile

from elftriage.imports import resolve_dangerous_imports
from elftriage.disassembly import disassemble_call_sites


def test_finds_call_sites(bin_ls_elffile: ELFFile) -> None:
    """Should find call sites for dangerous imports in /bin/ls."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    if not imports:
        return  # Skip if no imports found
    call_sites = disassemble_call_sites(bin_ls_elffile, imports)
    assert len(call_sites) > 0, "Should find at least one call site"


def test_call_site_has_context(bin_ls_elffile: ELFFile) -> None:
    """Each call site should have disassembly context lines."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    call_sites = disassemble_call_sites(bin_ls_elffile, imports, context_lines=3)
    for site in call_sites:
        assert len(site.disassembly_lines) > 0, "Call site should have context"
        assert site.address > 0, "Call site address should be positive"
        assert site.function_name, "Function name should not be empty"


def test_empty_imports_returns_empty(bin_ls_elffile: ELFFile) -> None:
    """No imports means no call sites."""
    call_sites = disassemble_call_sites(bin_ls_elffile, [])
    assert call_sites == []
