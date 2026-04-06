"""Function boundary detection for ELF binaries.

Detects function boundaries using symbol table information (when available)
and falls back to prologue-based heuristics for stripped binaries.
"""

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from elftriage.types import FunctionBoundary


def detect_functions(elffile: ELFFile) -> list[FunctionBoundary]:
    """Detect function boundaries in the binary.

    Tries symbol-based detection first (.symtab, then .dynsym), and
    falls back to prologue heuristics for stripped binaries.

    Args:
        elffile: A parsed ELF file object.

    Returns:
        List of detected function boundaries, sorted by start address.
    """
    functions = _detect_from_symbols(elffile)
    if not functions:
        functions = _detect_from_prologues(elffile)
    return sorted(functions, key=lambda f: f.start_address)


def find_containing_function(
    address: int,
    functions: list[FunctionBoundary],
) -> str:
    """Find the function containing a given address.

    Uses binary search on the sorted function list.

    Args:
        address: The instruction address to look up.
        functions: Sorted list of function boundaries.

    Returns:
        The function name, or empty string if not found.
    """
    lo, hi = 0, len(functions) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        func = functions[mid]
        if func.start_address <= address < func.end_address:
            return func.name
        elif address < func.start_address:
            hi = mid - 1
        else:
            lo = mid + 1
    return ""


def _detect_from_symbols(elffile: ELFFile) -> list[FunctionBoundary]:
    """Detect functions from symbol table entries of type STT_FUNC."""
    functions: list[FunctionBoundary] = []

    for section_name in (".symtab", ".dynsym"):
        section = elffile.get_section_by_name(section_name)
        if section is None or not isinstance(section, SymbolTableSection):
            continue

        for symbol in section.iter_symbols():
            if (
                symbol["st_info"]["type"] == "STT_FUNC"
                and symbol["st_value"] != 0
                and symbol["st_size"] > 0
            ):
                functions.append(
                    FunctionBoundary(
                        name=symbol.name or f"sub_{symbol['st_value']:x}",
                        start_address=symbol["st_value"],
                        end_address=symbol["st_value"] + symbol["st_size"],
                    )
                )

        if functions:
            break

    return functions


def _detect_from_prologues(elffile: ELFFile) -> list[FunctionBoundary]:
    """Detect functions by scanning for common x86_64 function prologues.

    Looks for patterns like:
      - push rbp; mov rbp, rsp  (standard frame pointer)
      - endbr64; push rbp       (CET-enabled binaries)
      - sub rsp, imm            (frameless functions)
    """
    text_section = elffile.get_section_by_name(".text")
    if text_section is None:
        return []

    text_data = text_section.data()
    text_addr = text_section.header.sh_addr
    functions: list[FunctionBoundary] = []

    # Standard prologue: push rbp (0x55) followed by mov rbp, rsp (0x48 0x89 0xe5)
    PUSH_RBP = 0x55
    MOV_RBP_RSP = bytes([0x48, 0x89, 0xE5])
    # CET prologue: endbr64 (f3 0f 1e fa)
    ENDBR64 = bytes([0xF3, 0x0F, 0x1E, 0xFA])

    i = 0
    while i < len(text_data) - 4:
        is_prologue = False

        # Check for endbr64 + push rbp
        if (
            text_data[i : i + 4] == ENDBR64
            and i + 4 < len(text_data)
            and text_data[i + 4] == PUSH_RBP
        ):
            is_prologue = True

        # Check for push rbp + mov rbp, rsp
        elif (
            text_data[i] == PUSH_RBP
            and i + 1 + 3 <= len(text_data)
            and text_data[i + 1 : i + 4] == MOV_RBP_RSP
        ):
            is_prologue = True

        if is_prologue:
            func_addr = text_addr + i
            functions.append(
                FunctionBoundary(
                    name=f"sub_{func_addr:x}",
                    start_address=func_addr,
                    # End address estimated as start of next function
                    end_address=0,
                )
            )

        i += 1

    # Fill in end addresses: each function ends where the next begins,
    # last function ends at end of .text
    text_end = text_addr + len(text_data)
    for j in range(len(functions) - 1):
        functions[j].end_address = functions[j + 1].start_address
    if functions:
        functions[-1].end_address = text_end

    return functions
