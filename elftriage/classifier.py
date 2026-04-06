"""Heuristic risk classifier for ranking findings by severity."""

from elftriage.types import (
    CallSite,
    DangerousImport,
    Finding,
    ProtectionInfo,
)

# Base scores by category
_CATEGORY_SCORES: dict[str, float] = {
    "critical": 10.0,
    "warning": 5.0,
    "mitigated": 2.0,
}

# Multiplier when protections are absent
_MISSING_PROTECTION_BONUS = 1.5


def classify_findings(
    imports: list[DangerousImport],
    call_sites: list[CallSite],
    protections: ProtectionInfo,
) -> list[Finding]:
    """Classify and rank findings by severity.

    Scoring heuristic:
    - Base score from function category (critical > warning > mitigated).
    - Multiplied if key protections (NX, canary) are absent.
    - Scaled by number of call sites (more call sites = more exposure).

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

        severity = base_score * protection_multiplier * site_factor

        findings.append(
            Finding(
                dangerous_import=imp,
                call_sites=func_sites,
                severity_score=round(severity, 2),
            )
        )

    findings.sort(key=lambda f: f.severity_score, reverse=True)
    return findings


def _compute_protection_multiplier(protections: ProtectionInfo) -> float:
    """Compute a multiplier based on missing protections."""
    multiplier = 1.0
    if not protections.nx:
        multiplier *= _MISSING_PROTECTION_BONUS
    if not protections.canary:
        multiplier *= _MISSING_PROTECTION_BONUS
    if protections.relro == "none":
        multiplier *= 1.2
    return multiplier
