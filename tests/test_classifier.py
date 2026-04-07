"""Tests for heuristic risk classifier."""

from elftriage.classifier import classify_findings
from elftriage.stackframe import StackFrameLayout, StackSlot
from elftriage.types import (
    ArgSource,
    ArgumentInfo,
    CallSite,
    ConditionConfidence,
    DangerousImport,
    ProtectionInfo,
    Reachability,
)


def _conditions_by_name(finding: object) -> dict[str, object]:
    return {c.name: c for c in finding.exploit_conditions}  # type: ignore[attr-defined]


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


def test_dest_is_stack_is_inferred_with_caveats() -> None:
    """A slice-detected stack destination must be INFERRED + carry caveats."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
    )

    findings = classify_findings(imports, [site], protections)
    cond = _conditions_by_name(findings[0])["dest_is_stack"]
    assert cond.satisfied is True  # type: ignore[attr-defined]
    confidence = cond.confidence  # type: ignore[attr-defined]
    assert confidence == ConditionConfidence.INFERRED
    caveats = cond.caveats  # type: ignore[attr-defined]
    assert caveats, "dest_is_stack must carry caveats when INFERRED"
    assert "aliasing not modeled" in caveats


def test_source_is_input_is_inferred_with_caveats() -> None:
    """A slice-detected input source must be INFERRED + carry caveats."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        arguments=[
            ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40"),
            ArgumentInfo("rsi", ArgSource.INPUT, "return value of read"),
        ],
    )

    findings = classify_findings(imports, [site], protections)
    cond = _conditions_by_name(findings[0])["source_is_input"]
    assert cond.satisfied is True  # type: ignore[attr-defined]
    assert cond.confidence == ConditionConfidence.INFERRED  # type: ignore[attr-defined]
    assert cond.caveats  # type: ignore[attr-defined]


def test_protection_conditions_remain_confirmed() -> None:
    """no_canary, no_pie, no_nx, no_relro stay CONFIRMED — they read header data."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo(nx=False, canary=False, pie=False, relro="none")

    findings = classify_findings(imports, [], protections)
    conds = _conditions_by_name(findings[0])
    for name in ("no_canary", "no_pie", "no_nx", "no_relro", "critical_function"):
        actual = conds[name].confidence  # type: ignore[attr-defined]
        assert actual == ConditionConfidence.CONFIRMED, name


def test_copy_size_exceeds_buffer_satisfied() -> None:
    """copy_size > slot.size_estimate must produce a satisfied INFERRED condition."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="vuln",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=0x100,
    )
    layout = StackFrameLayout(
        function_name="vuln",
        function_start=0x4000,
        frame_base="rbp",
        slots=[
            StackSlot(offset=-0x40, size_estimate=0x40),
            StackSlot(offset=-0x00, size_estimate=0),
        ],
        has_frame_pointer=True,
        confidence="high",
    )

    findings = classify_findings(imports, [site], protections, {"vuln": layout})
    cond = _conditions_by_name(findings[0])["copy_size_exceeds_buffer"]
    assert cond.satisfied is True  # type: ignore[attr-defined]
    assert cond.confidence == ConditionConfidence.INFERRED  # type: ignore[attr-defined]
    assert any("upper bound" in c for c in cond.caveats)  # type: ignore[attr-defined]


def test_copy_size_exceeds_buffer_unknown_when_no_size() -> None:
    """No copy_size means the condition is UNKNOWN, not falsely satisfied."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="vuln",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=None,
    )
    findings = classify_findings(imports, [site], protections)
    cond = _conditions_by_name(findings[0])["copy_size_exceeds_buffer"]
    assert cond.satisfied is False  # type: ignore[attr-defined]
    assert cond.confidence == ConditionConfidence.UNKNOWN  # type: ignore[attr-defined]


def test_reachability_unavailable_when_no_map() -> None:
    """No reachability map → condition is UNKNOWN with installation caveat."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo()
    findings = classify_findings(imports, [], protections)
    cond = _conditions_by_name(findings[0])["reachable_from_entry"]
    assert cond.satisfied is False  # type: ignore[attr-defined]
    assert cond.confidence == ConditionConfidence.UNKNOWN  # type: ignore[attr-defined]
    caveats = cond.caveats  # type: ignore[attr-defined]
    assert any("callgraph" in c for c in caveats)
    assert findings[0].reachability == Reachability.UNKNOWN


def test_reachability_reachable_inferred_with_caveats() -> None:
    """REACHABLE state → condition INFERRED (call graph is heuristic)."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo()
    site = CallSite(0x5000, "strcpy", containing_function="vuln")
    reach_map = {"vuln": Reachability.REACHABLE}

    findings = classify_findings(
        imports, [site], protections, reachability_by_func=reach_map
    )
    cond = _conditions_by_name(findings[0])["reachable_from_entry"]
    assert cond.satisfied is True  # type: ignore[attr-defined]
    assert cond.confidence == ConditionConfidence.INFERRED  # type: ignore[attr-defined]
    caveats = cond.caveats  # type: ignore[attr-defined]
    assert any("indirect" in c for c in caveats)
    assert findings[0].reachability == Reachability.REACHABLE


def test_reachability_no_static_path_is_unknown_not_unreachable() -> None:
    """A call graph that lacks an edge → UNKNOWN with dead-code caveat."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo()
    site = CallSite(0x5000, "strcpy", containing_function="vuln")
    # Empty map means: call graph available but no entry was found for vuln
    findings = classify_findings(imports, [site], protections, reachability_by_func={})
    cond = _conditions_by_name(findings[0])["reachable_from_entry"]
    assert cond.satisfied is False  # type: ignore[attr-defined]
    assert cond.confidence == ConditionConfidence.UNKNOWN  # type: ignore[attr-defined]
    caveats = cond.caveats  # type: ignore[attr-defined]
    assert any("dead code" in c for c in caveats)


def test_proved_unreachable_applies_penalty() -> None:
    """CONFIRMED unreachable applies a −2 score penalty."""
    imports = [DangerousImport("strcpy", "critical", "Overflow", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")

    baseline = classify_findings(imports, [], protections)

    site = CallSite(0x5000, "strcpy", containing_function="vuln")
    reach_map = {"vuln": Reachability.UNREACHABLE}
    penalized = classify_findings(
        imports, [site], protections, reachability_by_func=reach_map
    )

    assert penalized[0].severity_score <= baseline[0].severity_score


def test_dest_is_stack_promoted_to_confirmed_with_ir() -> None:
    """IR + non-escaping + non-recursive + constant copy_size → CONFIRMED."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="vuln",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=0x80,
        taint_method="ir",
        stack_dest_escapes=False,
    )
    findings = classify_findings(imports, [site], protections, recursive_funcs=set())
    cond = _conditions_by_name(findings[0])["dest_is_stack"]
    confidence = cond.confidence  # type: ignore[attr-defined]
    assert confidence == ConditionConfidence.CONFIRMED


def test_dest_is_stack_blocked_by_pointer_escape() -> None:
    """Even with IR, an escaping slot stays INFERRED with caveats."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="vuln",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=0x80,
        taint_method="ir",
        stack_dest_escapes=True,
    )
    findings = classify_findings(imports, [site], protections)
    cond = _conditions_by_name(findings[0])["dest_is_stack"]
    confidence = cond.confidence  # type: ignore[attr-defined]
    assert confidence == ConditionConfidence.INFERRED
    caveats = cond.caveats  # type: ignore[attr-defined]
    assert any("escape" in c for c in caveats)


def test_dest_is_stack_blocked_by_recursion() -> None:
    """A recursive function never promotes — slot reuse across invocations."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="recursive_func",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=0x80,
        taint_method="ir",
        stack_dest_escapes=False,
    )
    findings = classify_findings(
        imports, [site], protections, recursive_funcs={"recursive_func"}
    )
    cond = _conditions_by_name(findings[0])["dest_is_stack"]
    confidence = cond.confidence  # type: ignore[attr-defined]
    assert confidence == ConditionConfidence.INFERRED
    caveats = cond.caveats  # type: ignore[attr-defined]
    assert any("recursive" in c for c in caveats)


def test_dest_is_stack_blocked_without_constant_copy_size() -> None:
    """A non-constant copy_size keeps the condition at INFERRED."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="vuln",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=None,
        taint_method="ir",
        stack_dest_escapes=False,
    )
    findings = classify_findings(imports, [site], protections)
    cond = _conditions_by_name(findings[0])["dest_is_stack"]
    confidence = cond.confidence  # type: ignore[attr-defined]
    assert confidence == ConditionConfidence.INFERRED


def test_dest_is_stack_slice_path_never_promotes() -> None:
    """Slice-derived stack destinations always stay INFERRED."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="vuln",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=0x80,
        taint_method="slice",  # default; explicit for clarity
        stack_dest_escapes=None,
    )
    findings = classify_findings(imports, [site], protections)
    cond = _conditions_by_name(findings[0])["dest_is_stack"]
    confidence = cond.confidence  # type: ignore[attr-defined]
    assert confidence == ConditionConfidence.INFERRED
    caveats = cond.caveats  # type: ignore[attr-defined]
    # slice caveats, not IR caveats
    assert any("windowed slice" in c for c in caveats)


def test_copy_size_within_buffer_does_not_fire() -> None:
    """copy_size <= slot size must NOT mark the condition satisfied."""
    imports = [DangerousImport("memcpy", "warning", "Dangerous", 0x1000)]
    protections = ProtectionInfo(nx=True, canary=True, pie=True, relro="full")
    site = CallSite(
        0x5000,
        "memcpy",
        containing_function="vuln",
        arguments=[ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40")],
        copy_size=0x20,
    )
    layout = StackFrameLayout(
        function_name="vuln",
        function_start=0x4000,
        frame_base="rbp",
        slots=[StackSlot(offset=-0x40, size_estimate=0x40)],
        has_frame_pointer=True,
        confidence="high",
    )
    findings = classify_findings(imports, [site], protections, {"vuln": layout})
    cond = _conditions_by_name(findings[0])["copy_size_exceeds_buffer"]
    assert cond.satisfied is False  # type: ignore[attr-defined]
