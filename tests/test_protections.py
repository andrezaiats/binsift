"""Tests for binary protection detection."""

from elftools.elf.elffile import ELFFile

from elftriage.protections import detect_protections


def test_detect_protections_bin_ls(bin_ls_elffile: ELFFile) -> None:
    """Protection detection on /bin/ls should find standard hardening."""
    prot = detect_protections(bin_ls_elffile)

    assert prot.nx is True, "Modern /bin/ls should have NX enabled"
    assert prot.pie is True, "Modern /bin/ls should be PIE"
    assert prot.canary is True, "Modern /bin/ls should have stack canary"
    assert prot.relro in ("partial", "full"), "Modern /bin/ls should have RELRO"
    # FORTIFY is common but not guaranteed; just check it returns a bool
    assert isinstance(prot.fortify, bool)


def test_relro_value_is_valid(bin_ls_elffile: ELFFile) -> None:
    """RELRO should be one of the three valid values."""
    prot = detect_protections(bin_ls_elffile)
    assert prot.relro in ("none", "partial", "full")
