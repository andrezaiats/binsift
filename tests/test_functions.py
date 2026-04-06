"""Tests for function boundary detection."""

from elftools.elf.elffile import ELFFile

from elftriage.functions import detect_functions, find_containing_function
from elftriage.types import FunctionBoundary


def test_detect_functions_bin_ls(bin_ls_elffile: ELFFile) -> None:
    """Should detect functions in /bin/ls."""
    functions = detect_functions(bin_ls_elffile)
    assert len(functions) > 0, "Should detect at least one function"


def test_functions_sorted_by_address(bin_ls_elffile: ELFFile) -> None:
    """Functions should be sorted by start address."""
    functions = detect_functions(bin_ls_elffile)
    for i in range(len(functions) - 1):
        assert functions[i].start_address <= functions[i + 1].start_address


def test_functions_have_valid_bounds(bin_ls_elffile: ELFFile) -> None:
    """Each function should have start < end."""
    functions = detect_functions(bin_ls_elffile)
    for func in functions:
        assert func.start_address < func.end_address
        assert func.name, "Function should have a name"


def test_find_containing_function_hit() -> None:
    """Should find the function containing a given address."""
    functions = [
        FunctionBoundary("main", 0x1000, 0x1100),
        FunctionBoundary("helper", 0x1100, 0x1200),
        FunctionBoundary("cleanup", 0x1200, 0x1300),
    ]
    assert find_containing_function(0x1050, functions) == "main"
    assert find_containing_function(0x1150, functions) == "helper"
    assert find_containing_function(0x1200, functions) == "cleanup"


def test_find_containing_function_miss() -> None:
    """Should return empty string for an address not in any function."""
    functions = [
        FunctionBoundary("main", 0x1000, 0x1100),
    ]
    assert find_containing_function(0x900, functions) == ""
    assert find_containing_function(0x2000, functions) == ""


def test_find_containing_function_empty() -> None:
    """Should return empty string for an empty function list."""
    assert find_containing_function(0x1000, []) == ""
