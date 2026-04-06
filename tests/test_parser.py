"""Tests for ELF parser module."""

import tempfile

import pytest
from elftools.elf.elffile import ELFFile

from elftriage.parser import open_elf, parse_elf


def test_open_elf_context_manager(bin_ls_path: str) -> None:
    """Context manager should yield a valid ELFFile and close cleanly."""
    with open_elf(bin_ls_path) as elffile:
        assert isinstance(elffile, ELFFile)
        assert elffile.elfclass == 64


def test_open_elf_file_not_found() -> None:
    """Should raise FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        with open_elf("/nonexistent/binary"):
            pass


def test_open_elf_invalid_file() -> None:
    """Should raise ValueError for non-ELF files."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("not an elf file")
        path = f.name
    with pytest.raises(ValueError, match="Not a valid ELF"):
        with open_elf(path):
            pass


def test_parse_elf_legacy_returns_tuple(bin_ls_path: str) -> None:
    """Legacy parse_elf should return (ELFFile, file_handle) tuple."""
    elffile, fh = parse_elf(bin_ls_path)
    try:
        assert isinstance(elffile, ELFFile)
        assert not fh.closed
    finally:
        fh.close()
    assert fh.closed
