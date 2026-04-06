"""PLT/GOT resolver for identifying dangerous libc function imports."""

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from elftriage.types import DangerousImport
from elftriage import dangerous_functions


def resolve_dangerous_imports(elffile: ELFFile) -> list[DangerousImport]:
    """Resolve dangerous function imports from PLT relocations.

    Parses .rela.plt (or .rel.plt) to find relocations, resolves the symbol
    name for each, and checks against the dangerous functions database.

    Args:
        elffile: A parsed ELF file object.

    Returns:
        List of dangerous imports found in the binary.
    """
    imports: list[DangerousImport] = []

    dynsym = elffile.get_section_by_name(".dynsym")
    if dynsym is None or not isinstance(dynsym, SymbolTableSection):
        return imports

    plt_section = elffile.get_section_by_name(".plt")
    plt_base = plt_section.header.sh_addr if plt_section else 0
    # Standard PLT entry size on x86_64 is 16 bytes
    plt_entry_size = plt_section.header.sh_entsize if plt_section else 16
    if plt_entry_size == 0:
        plt_entry_size = 16

    rela_plt = _find_relocation_section(elffile)
    if rela_plt is None:
        return imports

    for idx, reloc in enumerate(rela_plt.iter_relocations()):
        sym_idx = reloc["r_info_sym"]
        symbol = dynsym.get_symbol(sym_idx)
        if symbol is None:
            continue

        name = symbol.name
        result = dangerous_functions.lookup(name)
        if result is None:
            continue

        category, risk_description = result
        # PLT entry address: base + (index + 1) * entry_size
        # The +1 accounts for the PLT[0] stub
        plt_addr = plt_base + (idx + 1) * plt_entry_size

        imports.append(
            DangerousImport(
                name=name,
                category=category,
                risk_description=risk_description,
                plt_address=plt_addr,
            )
        )

    return imports


def _find_relocation_section(
    elffile: ELFFile,
) -> RelocationSection | None:
    """Find the PLT relocation section (.rela.plt or .rel.plt)."""
    for name in (".rela.plt", ".rel.plt", ".rela.dyn"):
        section = elffile.get_section_by_name(name)
        if isinstance(section, RelocationSection):
            return section  # type: ignore[no-any-return]
    return None
