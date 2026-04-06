"""Heuristic risk classifier for ranking findings by severity.

Scores findings based on:
- Function danger category (critical > warning > format_string > mitigated)
- Missing binary protections (NX, canary, PIE, RELRO)
- Number and nature of call sites
- Argument provenance (stack buffers, input sources)
- Format string risk

Generates exploitability notes that explain *why* a finding is dangerous
in the context of this specific binary's protections and call patterns.
"""

from elftriage.types import (
    ArgSource,
    CallSite,
    DangerousImport,
    Finding,
    ProtectionInfo,
)

# Base scores by category
_CATEGORY_SCORES: dict[str, float] = {
    "critical": 10.0,
    "warning": 5.0,
    "format_string": 7.0,
    "mitigated": 2.0,
}


def classify_findings(
    imports: list[DangerousImport],
    call_sites: list[CallSite],
    protections: ProtectionInfo,
) -> list[Finding]:
    """Classify and rank findings by severity.

    Scoring formula:
        severity = base_score * protection_mult * site_factor * arg_factor

    Generates human-readable exploitability notes for each finding that
    cross-reference the specific protections, argument sources, and
    call patterns.

    Args:
        imports: List of dangerous imports found in the binary.
        call_sites: List of call sites referencing dangerous functions.
        protections: Binary protection status.

    Returns:
        List of findings sorted by severity score (highest first).
    """
    # Group call sites by function name
    sites_by_func: dict[str, list[CallSite]] = {}
    for site in call_sites:
        sites_by_func.setdefault(site.function_name, []).append(site)

    protection_multiplier = _compute_protection_multiplier(protections)

    findings: list[Finding] = []
    for imp in imports:
        func_sites = sites_by_func.get(imp.name, [])
        base_score = _CATEGORY_SCORES.get(imp.category, 1.0)

        # Scale by call site count (at least 1.0)
        site_factor = max(1.0, len(func_sites) * 0.5 + 0.5)

        # Argument-based multiplier
        arg_factor = _compute_arg_factor(func_sites)

        severity = base_score * protection_multiplier * site_factor * arg_factor

        # Generate exploitability notes
        notes = _generate_exploitability_notes(imp, func_sites, protections)

        findings.append(
            Finding(
                dangerous_import=imp,
                call_sites=func_sites,
                severity_score=round(severity, 2),
                exploitability_notes=notes,
            )
        )

    findings.sort(key=lambda f: f.severity_score, reverse=True)
    return findings


def _compute_protection_multiplier(protections: ProtectionInfo) -> float:
    """Compute a multiplier based on missing protections."""
    multiplier = 1.0
    if not protections.nx:
        multiplier *= 1.5
    if not protections.canary:
        multiplier *= 1.5
    if not protections.pie:
        multiplier *= 1.3
    if protections.relro == "none":
        multiplier *= 1.2
    return multiplier


def _compute_arg_factor(call_sites: list[CallSite]) -> float:
    """Compute a multiplier based on argument analysis results.

    Stack-targeted writes and input-sourced data increase the score.
    """
    if not call_sites:
        return 1.0

    max_factor = 1.0
    for site in call_sites:
        factor = 1.0
        for arg in site.arguments:
            if arg.source == ArgSource.STACK:
                factor = max(factor, 1.4)
            elif arg.source == ArgSource.INPUT:
                factor = max(factor, 1.6)
        if site.is_format_string_risk:
            factor = max(factor, 1.5)
        max_factor = max(max_factor, factor)

    return max_factor


def _generate_exploitability_notes(
    imp: DangerousImport,
    call_sites: list[CallSite],
    protections: ProtectionInfo,
) -> list[str]:
    """Generate context-aware exploitability notes.

    Explains the specific risk of this finding given the binary's
    protections and the argument analysis results.
    """
    notes: list[str] = []

    # Protection-aware notes
    if imp.category == "critical":
        if not protections.canary:
            notes.append(
                f"{imp.name} with no stack canary: stack buffer overflow "
                "can overwrite return address without detection"
            )
        if not protections.pie:
            notes.append(
                f"No PIE: addresses are predictable, simplifying "
                f"ROP/ret2libc exploitation of {imp.name}"
            )
        if not protections.nx:
            notes.append(
                f"No NX: shellcode on the stack is executable, "
                f"{imp.name} overflow could lead to direct code execution"
            )

    # Argument-aware notes
    has_stack_dest = False
    has_input_src = False
    has_fmt_risk = False

    for site in call_sites:
        if site.is_format_string_risk:
            has_fmt_risk = True

        for arg in site.arguments:
            if arg.register == "rdi" and arg.source == ArgSource.STACK:
                has_stack_dest = True
            if arg.source == ArgSource.INPUT:
                has_input_src = True

    if has_stack_dest and imp.category in ("critical", "warning"):
        notes.append(
            f"{imp.name} writes to a stack buffer: overflow can corrupt "
            "the saved return pointer and control flow"
        )

    if has_input_src:
        notes.append(
            f"{imp.name} receives data from an input source (read/recv): "
            "attacker-controlled content may reach this call"
        )

    if has_fmt_risk:
        notes.append(
            f"{imp.name} format argument is not a string literal: "
            "attacker-controlled format string can leak stack data "
            "or write arbitrary memory via %n"
        )

    # Cross-reference notes
    if has_stack_dest and not protections.canary and imp.category == "critical":
        notes.append(
            "HIGH RISK: stack-targeted write + no canary + critical function "
            "= classic exploitable stack overflow"
        )

    if has_stack_dest and not protections.canary and not protections.pie:
        notes.append(
            "EXPLOIT CHAIN: stack overflow → overwrite return address "
            "(no canary) → jump to known address (no PIE)"
        )

    return notes
