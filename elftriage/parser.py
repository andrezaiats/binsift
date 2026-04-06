"""ELF parsing layer — opens and validates ELF binaries using pyelftools."""

from io import BufferedReader
from pathlib import Path

from elftools.elf.elffile import ELFFile


def parse_elf(path: str) -> tuple[ELFFile, BufferedReader]:
    """Open and validate an ELF binary.

    Checks that the file is a valid ELF64 x86_64 dynamically-linked binary.

    Args:
        path: Path to the ELF binary.

    Returns:
        A tuple of (ELFFile, open file handle). The caller must keep the
        file handle alive for the lifetime of the ELFFile object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a supported ELF binary.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    f = open(file_path, "rb")
    try:
        elffile = ELFFile(f)
    except Exception as exc:
        f.close()
        raise ValueError(f"Not a valid ELF file: {path}") from exc

    if elffile.elfclass != 64:
        f.close()
        raise ValueError(
            f"Unsupported ELF class: {elffile.elfclass}-bit (only 64-bit supported)"
        )

    arch = elffile.header.e_machine
    if arch != "EM_X86_64":
        f.close()
        raise ValueError(f"Unsupported architecture: {arch} (only x86_64 supported)")

    # Check for dynamic linking by looking for PT_DYNAMIC segment
    has_dynamic = any(
        seg.header.p_type == "PT_DYNAMIC" for seg in elffile.iter_segments()
    )
    if not has_dynamic:
        f.close()
        raise ValueError(
            f"Binary appears to be statically linked: {path} "
            "(only dynamically linked binaries are supported)"
        )

    return elffile, f
