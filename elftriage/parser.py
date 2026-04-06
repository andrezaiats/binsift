"""ELF parsing layer — opens and validates ELF binaries using pyelftools."""

from contextlib import contextmanager
from io import BufferedReader
from pathlib import Path
from typing import Generator

from elftools.elf.elffile import ELFFile


@contextmanager
def open_elf(path: str) -> Generator[ELFFile, None, None]:
    """Open and validate an ELF binary as a context manager.

    Checks that the file is a valid ELF64 x86_64 dynamically-linked binary.
    The file handle is automatically closed when the context exits.

    Args:
        path: Path to the ELF binary.

    Yields:
        A validated ELFFile object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a supported ELF binary.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    f: BufferedReader = open(file_path, "rb")  # type: ignore[assignment]
    try:
        try:
            elffile = ELFFile(f)
        except Exception as exc:
            raise ValueError(f"Not a valid ELF file: {path}") from exc

        if elffile.elfclass != 64:
            raise ValueError(
                f"Unsupported ELF class: {elffile.elfclass}-bit "
                "(only 64-bit supported)"
            )

        arch = elffile.header.e_machine
        if arch != "EM_X86_64":
            raise ValueError(
                f"Unsupported architecture: {arch} (only x86_64 supported)"
            )

        has_dynamic = any(
            seg.header.p_type == "PT_DYNAMIC" for seg in elffile.iter_segments()
        )
        if not has_dynamic:
            raise ValueError(
                f"Binary appears to be statically linked: {path} "
                "(only dynamically linked binaries are supported)"
            )

        yield elffile
    finally:
        f.close()


def parse_elf(path: str) -> tuple[ELFFile, BufferedReader]:
    """Open and validate an ELF binary (legacy interface).

    Prefer open_elf() context manager for new code. This function is kept
    for backward compatibility.

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
