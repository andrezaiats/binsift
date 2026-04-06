"""Database of dangerous libc functions and their risk classifications."""

from typing import Optional

# (category, risk_description)
_DATABASE: dict[str, tuple[str, str]] = {
    # Always dangerous — critical
    "gets": ("critical", "No bounds checking, always exploitable"),
    "strcpy": ("critical", "No length limit, classic overflow source"),
    "strcat": ("critical", "No length limit on concatenation"),
    "sprintf": ("critical", "No output bounds checking"),
    "vsprintf": ("critical", "No output bounds checking"),
    # Context-dependent — warning
    "memcpy": ("warning", "Dangerous if size is user-controlled"),
    "memmove": ("warning", "Dangerous if size is user-controlled"),
    "strncpy": ("warning", "Silent truncation can cause logic bugs"),
    "strncat": ("warning", "Off-by-one errors are common"),
    "snprintf": ("warning", "Return value misuse can cause issues"),
    "scanf": ("warning", "%s without width is unbounded"),
    "fscanf": ("warning", "%s without width is unbounded"),
    "sscanf": ("warning", "%s without width is unbounded"),
    "read": ("warning", "Safe by itself, but buffer sizing matters"),
    "recv": ("warning", "Safe by itself, but buffer sizing matters"),
    # Fortified variants — mitigated
    "__strcpy_chk": ("mitigated", "FORTIFY_SOURCE-protected strcpy"),
    "__memcpy_chk": ("mitigated", "FORTIFY_SOURCE-protected memcpy"),
    "__sprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected sprintf"),
    "__gets_chk": ("mitigated", "FORTIFY_SOURCE-protected gets (still risky)"),
    "__strcat_chk": ("mitigated", "FORTIFY_SOURCE-protected strcat"),
    "__snprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected snprintf"),
    "__vsprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected vsprintf"),
    "__memmove_chk": ("mitigated", "FORTIFY_SOURCE-protected memmove"),
}


def lookup(name: str) -> Optional[tuple[str, str]]:
    """Look up a function name in the dangerous functions database.

    Args:
        name: The function name to look up.

    Returns:
        A tuple of (category, risk_description) if found, None otherwise.
    """
    return _DATABASE.get(name)


def all_functions() -> dict[str, tuple[str, str]]:
    """Return the full dangerous functions database.

    Returns:
        A dict mapping function name to (category, risk_description).
    """
    return dict(_DATABASE)
