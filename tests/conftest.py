"""Shared test fixtures."""

import pytest

from elftools.elf.elffile import ELFFile

# /bin/ls is a real x86_64 dynamically-linked ELF on this system
BIN_LS = "/bin/ls"


@pytest.fixture
def bin_ls_path() -> str:
    """Path to /bin/ls for integration testing."""
    return BIN_LS


@pytest.fixture
def bin_ls_elffile() -> ELFFile:
    """Parsed ELFFile for /bin/ls. Caller must not close the underlying file."""
    f = open(BIN_LS, "rb")
    elffile = ELFFile(f)
    yield elffile  # type: ignore[misc]
    f.close()
