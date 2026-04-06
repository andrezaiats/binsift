"""Tests for the dangerous functions database."""

from elftriage.dangerous_functions import (
    lookup,
    all_functions,
    get_format_arg_index,
)


def test_lookup_critical() -> None:
    """Critical functions should return correct category."""
    result = lookup("gets")
    assert result is not None
    category, desc = result
    assert category == "critical"
    assert desc


def test_lookup_warning() -> None:
    """Warning functions should return correct category."""
    result = lookup("memcpy")
    assert result is not None
    assert result[0] == "warning"


def test_lookup_mitigated() -> None:
    """Fortified variants should return mitigated category."""
    result = lookup("__strcpy_chk")
    assert result is not None
    assert result[0] == "mitigated"


def test_lookup_format_string() -> None:
    """Format string functions should return format_string category."""
    result = lookup("printf")
    assert result is not None
    assert result[0] == "format_string"


def test_lookup_unknown() -> None:
    """Unknown functions should return None."""
    assert lookup("my_custom_func") is None


def test_all_functions_returns_copy() -> None:
    """all_functions should return a separate copy."""
    db = all_functions()
    db["test"] = ("test", "test")
    assert lookup("test") is None


def test_format_arg_index_printf() -> None:
    """printf format arg is at index 0."""
    assert get_format_arg_index("printf") == 0


def test_format_arg_index_fprintf() -> None:
    """fprintf format arg is at index 1."""
    assert get_format_arg_index("fprintf") == 1


def test_format_arg_index_snprintf() -> None:
    """snprintf format arg is at index 2."""
    assert get_format_arg_index("snprintf") == 2


def test_format_arg_index_non_format() -> None:
    """Non-format functions should return None."""
    assert get_format_arg_index("memcpy") is None


def test_all_categories_valid() -> None:
    """All entries should have valid categories."""
    valid = {"critical", "warning", "mitigated", "format_string"}
    for name, (category, desc) in all_functions().items():
        assert category in valid, f"{name} has invalid category: {category}"
        assert desc, f"{name} has empty description"
