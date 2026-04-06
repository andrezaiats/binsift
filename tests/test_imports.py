"""Tests for PLT/GOT dangerous import resolution."""

from elftools.elf.elffile import ELFFile

from elftriage.imports import resolve_dangerous_imports


def test_resolve_finds_imports(bin_ls_elffile: ELFFile) -> None:
    """Should find at least one dangerous import in /bin/ls."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    assert len(imports) > 0, "/bin/ls should have at least one dangerous import"


def test_import_fields_populated(bin_ls_elffile: ELFFile) -> None:
    """Each import should have all fields populated."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    for imp in imports:
        assert imp.name, "Import name should not be empty"
        assert imp.category in ("critical", "warning", "mitigated")
        assert imp.risk_description, "Risk description should not be empty"
        assert imp.plt_address > 0, "PLT address should be positive"


def test_categories_are_valid(bin_ls_elffile: ELFFile) -> None:
    """All import categories should be from the known set."""
    imports = resolve_dangerous_imports(bin_ls_elffile)
    valid = {"critical", "warning", "mitigated"}
    for imp in imports:
        assert imp.category in valid
