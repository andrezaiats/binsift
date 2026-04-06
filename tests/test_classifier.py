"""Tests for heuristic risk classifier."""

from elftriage.classifier import classify_findings
from elftriage.types import (
    ArgSource,
    ArgumentInfo,
    CallSite,
    DangerousImport,
    ProtectionInfo,
)


def test_critical_ranked_above_warning() -> None:
    """Critical findings should score higher than warnings."""
    imports = [
        DangerousImport("gets", "critical", "Always dangerous", 0x1000),
        DangerousImport("memcpy", "warning", "Context dependent", 0x2000),
    ]
    protections = ProtectionInfo(nx=True, pie=True, canary=True, relro="full")
    findings = classify_findings(imports, [], protections)

    assert findings[0].dangerous_import.name == "gets"
    assert findings[0].severity_score > findings[1].severity_score


def test_missing_protections_increase_score() -> None:
    """Missing NX and canary should increase severity scores."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]

    hardened = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    weak = ProtectionInfo(nx=False, canary=False, pie=False, relro="none")

    hardened_findings = classify_findings(imports, [], hardened)
    weak_findings = classify_findings(imports, [], weak)

    assert weak_findings[0].severity_score > hardened_findings[0].severity_score


def test_pie_absence_increases_score() -> None:
    """Missing PIE should increase severity scores."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]

    with_pie = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    no_pie = ProtectionInfo(nx=True, canary=True, pie=False, relro="full")

    pie_findings = classify_findings(imports, [], with_pie)
    nopie_findings = classify_findings(imports, [], no_pie)

    assert nopie_findings[0].severity_score > pie_findings[0].severity_score


def test_more_call_sites_increase_score() -> None:
    """More call sites should result in a higher score."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")

    few_sites = [CallSite(0x5000, "strcpy")]
    many_sites = [CallSite(0x5000 + i, "strcpy") for i in range(10)]

    few_findings = classify_findings(imports, few_sites, protections)
    many_findings = classify_findings(imports, many_sites, protections)

    assert many_findings[0].severity_score > few_findings[0].severity_score


def test_stack_arg_increases_score() -> None:
    """Call sites with stack-targeted arguments should score higher."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")

    plain_site = CallSite(0x5000, "memcpy")
    stack_site = CallSite(
        0x5000,
        "memcpy",
        arguments=[
            ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40"),
        ],
    )

    plain_findings = classify_findings(imports, [plain_site], protections)
    stack_findings = classify_findings(imports, [stack_site], protections)

    assert stack_findings[0].severity_score > plain_findings[0].severity_score


def test_exploitability_notes_generated() -> None:
    """Findings with missing protections should have exploitability notes."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo(nx=False, canary=False, pie=False, relro="none")

    findings = classify_findings(imports, [], protections)
    assert len(findings[0].exploitability_notes) > 0


def test_exploit_chain_note() -> None:
    """Stack write + no canary + no PIE should produce exploit chain note."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=False, pie=False, relro="full")

    stack_site = CallSite(
        0x5000,
        "strcpy",
        arguments=[
            ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40"),
        ],
    )

    findings = classify_findings(imports, [stack_site], protections)
    notes_text = " ".join(findings[0].exploitability_notes)
    assert "EXPLOIT CHAIN" in notes_text


def test_format_string_risk_increases_score() -> None:
    """Call sites with format string risk should score higher."""
    imports = [DangerousImport("printf", "format_string", "Fmt risk", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")

    safe_site = CallSite(0x5000, "printf", is_format_string_risk=False)
    risky_site = CallSite(0x5000, "printf", is_format_string_risk=True)

    safe_findings = classify_findings(imports, [safe_site], protections)
    risky_findings = classify_findings(imports, [risky_site], protections)

    assert risky_findings[0].severity_score > safe_findings[0].severity_score


def test_empty_imports() -> None:
    """No imports should return no findings."""
    findings = classify_findings([], [], ProtectionInfo())
    assert findings == []
