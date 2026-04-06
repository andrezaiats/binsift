"""Database of dangerous libc functions and their risk classifications."""

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
    # Format string — potential format string vulnerability
    "printf": ("format_string", "Format string bug if format arg is not a literal"),
    "fprintf": ("format_string", "Format string bug if format arg is not a literal"),
    "dprintf": ("format_string", "Format string bug if format arg is not a literal"),
    "syslog": ("format_string", "Format string bug if format arg is not a literal"),
    "vprintf": ("format_string", "Format string bug if format arg is not a literal"),
    "vfprintf": ("format_string", "Format string bug if format arg is not a literal"),
    # Fortified variants — mitigated
    "__strcpy_chk": ("mitigated", "FORTIFY_SOURCE-protected strcpy"),
    "__memcpy_chk": ("mitigated", "FORTIFY_SOURCE-protected memcpy"),
    "__sprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected sprintf"),
    "__gets_chk": ("mitigated", "FORTIFY_SOURCE-protected gets (still risky)"),
    "__strcat_chk": ("mitigated", "FORTIFY_SOURCE-protected strcat"),
    "__snprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected snprintf"),
    "__vsprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected vsprintf"),
    "__memmove_chk": ("mitigated", "FORTIFY_SOURCE-protected memmove"),
    "__printf_chk": ("mitigated", "FORTIFY_SOURCE-protected printf"),
    "__fprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected fprintf"),
    "__vprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected vprintf"),
    "__vfprintf_chk": ("mitigated", "FORTIFY_SOURCE-protected vfprintf"),
    "__syslog_chk": ("mitigated", "FORTIFY_SOURCE-protected syslog"),
}

# Functions where the first user-controlled argument is the format string.
# Maps function name to the 0-based argument index of the format parameter.
FORMAT_STRING_FUNCTIONS: dict[str, int] = {
    "printf": 0,
    "fprintf": 1,  # fprintf(FILE*, fmt, ...)
    "dprintf": 1,  # dprintf(fd, fmt, ...)
    "syslog": 1,  # syslog(priority, fmt, ...)
    "vprintf": 0,
    "vfprintf": 1,
    "sprintf": 1,  # sprintf(buf, fmt, ...)
    "snprintf": 2,  # snprintf(buf, size, fmt, ...)
}


def lookup(name: str) -> tuple[str, str] | None:
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


def get_format_arg_index(name: str) -> int | None:
    """Get the argument index of the format string for a function.

    Args:
        name: The function name.

    Returns:
        The 0-based argument index of the format parameter, or None
        if the function is not a format string function.
    """
    return FORMAT_STRING_FUNCTIONS.get(name)
