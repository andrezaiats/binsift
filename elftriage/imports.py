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
    Uses the relocation's r_offset to find the GOT entry, then resolves
    the corresponding PLT stub address.

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
    plt_sec_section = elffile.get_section_by_name(".plt.sec")

    rela_plt = _find_plt_relocation_section(elffile)
    if rela_plt is None:
        return imports

    # Build a GOT offset → PLT index map. Each relocation in .rela.plt
    # corresponds to a PLT entry in order. The PLT stub address is then:
    #   - .plt.sec base + index * entry_size  (if .plt.sec exists, e.g. CET)
    #   - .plt base + (index + 1) * entry_size  (traditional layout)
    if plt_sec_section is not None:
        plt_base = plt_sec_section.header.sh_addr
        plt_entry_size = plt_sec_section.header.sh_entsize or 16
        index_offset = 0
    elif plt_section is not None:
        plt_base = plt_section.header.sh_addr
        plt_entry_size = plt_section.header.sh_entsize or 16
        # Skip PLT[0] which is the resolver stub
        index_offset = 1
    else:
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
        got_addr = reloc["r_offset"]
        plt_addr = plt_base + (idx + index_offset) * plt_entry_size

        imports.append(
            DangerousImport(
                name=name,
                category=category,
                risk_description=risk_description,
                plt_address=plt_addr,
                got_address=got_addr,
            )
        )

    return imports


def _find_plt_relocation_section(
    elffile: ELFFile,
) -> RelocationSection | None:
    """Find the PLT relocation section (.rela.plt or .rel.plt).

    Does NOT fall back to .rela.dyn, which contains non-PLT relocations
    (GLOB_DAT, RELATIVE) that would produce incorrect PLT addresses.
    """
    for name in (".rela.plt", ".rel.plt"):
        section = elffile.get_section_by_name(name)
        if isinstance(section, RelocationSection):
            return section  # type: ignore[no-any-return]
    return None
