"""Detection of binary protections: NX, PIE, canary, RELRO, FORTIFY_SOURCE."""

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

from elftriage.types import ProtectionInfo


def detect_protections(elffile: ELFFile) -> ProtectionInfo:
    """Detect binary protection mechanisms.

    Args:
        elffile: A parsed ELF file object.

    Returns:
        ProtectionInfo with all detected protections.
    """
    return ProtectionInfo(
        nx=_detect_nx(elffile),
        pie=_detect_pie(elffile),
        canary=_detect_canary(elffile),
        relro=_detect_relro(elffile),
        fortify=_detect_fortify(elffile),
    )


def _detect_nx(elffile: ELFFile) -> bool:
    """NX enabled if PT_GNU_STACK segment exists without execute flag."""
    for seg in elffile.iter_segments():
        if seg.header.p_type == "PT_GNU_STACK":
            # PF_X = 0x1; if not set, NX is enabled
            return bool((seg.header.p_flags & 0x1) == 0)
    # No PT_GNU_STACK usually means NX is enabled (modern default)
    return True


def _detect_pie(elffile: ELFFile) -> bool:
    """PIE enabled if ELF type is ET_DYN (shared object / PIE executable)."""
    return bool(elffile.header.e_type == "ET_DYN")


def _detect_canary(elffile: ELFFile) -> bool:
    """Stack canary present if __stack_chk_fail is in dynamic symbols."""
    dynsym = elffile.get_section_by_name(".dynsym")
    if dynsym is None:
        return False
    for symbol in dynsym.iter_symbols():
        if symbol.name == "__stack_chk_fail":
            return True
    return False


def _detect_relro(elffile: ELFFile) -> str:
    """Detect RELRO level.

    Returns:
        'none', 'partial', or 'full'.
    """
    has_relro_segment = False
    for seg in elffile.iter_segments():
        if seg.header.p_type == "PT_GNU_RELRO":
            has_relro_segment = True
            break

    if not has_relro_segment:
        return "none"

    # Check for BIND_NOW (Full RELRO requires both PT_GNU_RELRO and DT_BIND_NOW)
    for section in elffile.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag == "DT_BIND_NOW":
                return "full"
            if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):
                # DF_BIND_NOW = 0x8
                return "full"
            if tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):
                # DF_1_NOW = 0x1
                return "full"

    return "partial"


def _detect_fortify(elffile: ELFFile) -> bool:
    """FORTIFY_SOURCE detected if any __*_chk symbols are in dynamic symbols."""
    dynsym = elffile.get_section_by_name(".dynsym")
    if dynsym is None:
        return False
    for symbol in dynsym.iter_symbols():
        if symbol.name.startswith("__") and symbol.name.endswith("_chk"):
            return True
    return False
