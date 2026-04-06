"""Additive condition-based risk classifier for ranking findings by severity.

Builds a list of ExploitCondition objects for each finding, checking
protection status, argument provenance, format string risk, function
danger category, and call site density.  Computes a weighted sum
severity score (replacing the earlier multiplicative model) and
determines the most likely exploit primitive.

Also provides ``build_exploit_scenarios`` to group findings by
primitive into actionable exploit scenarios.
"""

from __future__ import annotations

from elftriage.stackframe import StackFrameLayout, estimate_distance_to_return_address
from elftriage.types import (
    ArgSource,
    CallSite,
    ConditionConfidence,
    DangerousImport,
    ExploitCondition,
    ExploitPrimitive,
    ExploitScenario,
    Finding,
    ProtectionInfo,
)

# Weights for each condition when computing the additive severity score.
_CONDITION_WEIGHTS: dict[str, float] = {
    "critical_function": 10,
    "no_canary": 8,
    "no_nx": 7,
    "dest_is_stack": 7,
    "source_is_input": 6,
    "no_pie": 5,
    "format_string_controlled": 8,
    "no_relro": 3,
    "multiple_call_sites": 2,
    "fortified": -5,
}

# Titles and descriptions for each exploit primitive scenario.
_SCENARIO_INFO: dict[ExploitPrimitive, tuple[str, str]] = {
    ExploitPrimitive.FLOW_CONTROL: (
        "Control Flow Hijack",
        "One or more findings may allow overwriting a return address "
        "or function pointer to redirect execution.",
    ),
    ExploitPrimitive.INFO_LEAK: (
        "Information Leak via Format String",
        "Format string vulnerabilities can leak stack or heap data "
        "to the attacker, defeating ASLR or exposing secrets.",
    ),
    ExploitPrimitive.ARBITRARY_WRITE: (
        "Arbitrary Write via Format String",
        "A format string vulnerability combined with weak RELRO can "
        "allow arbitrary memory writes through %n specifiers.",
    ),
    ExploitPrimitive.DOS: (
        "Denial of Service / Crash",
        "Findings that may cause crashes or undefined behaviour but "
        "do not clearly lead to code execution.",
    ),
}


def classify_findings(
    imports: list[DangerousImport],
    call_sites: list[CallSite],
    protections: ProtectionInfo,
    stack_layouts: dict[str, StackFrameLayout] | None = None,
) -> list[Finding]:
    """Classify and rank findings using an additive condition-based model.

    For each dangerous import, builds a list of exploit conditions,
    computes a weighted severity score, determines the exploit primitive,
    and generates human-readable exploitability notes.

    Args:
        imports: List of dangerous imports found in the binary.
        call_sites: List of call sites referencing dangerous functions.
        protections: Binary protection status.
        stack_layouts: Optional mapping of function name to its
            reconstructed stack frame layout.

    Returns:
        List of findings sorted by severity score (highest first).
    """
    sites_by_func: dict[str, list[CallSite]] = {}
    for site in call_sites:
        sites_by_func.setdefault(site.function_name, []).append(site)

    findings: list[Finding] = []
    for imp in imports:
        func_sites = sites_by_func.get(imp.name, [])

        conditions = _build_conditions(imp, func_sites, protections)
        score = _compute_severity_score(conditions)
        primitive = _determine_primitive(conditions, imp.category)

        # Look up stack frame layout for exploitability notes
        layout = _find_layout_for_sites(func_sites, stack_layouts)
        notes = _generate_exploitability_notes(imp, func_sites, protections, layout)

        findings.append(
            Finding(
                dangerous_import=imp,
                call_sites=func_sites,
                severity_score=score,
                exploitability_notes=notes,
                exploit_conditions=conditions,
                exploit_primitive=primitive,
            )
        )

    findings.sort(key=lambda f: f.severity_score, reverse=True)
    return findings


def build_exploit_scenarios(
    findings: list[Finding],
    protections: ProtectionInfo,
) -> list[ExploitScenario]:
    """Group findings by exploit primitive into actionable scenarios.

    Creates one ``ExploitScenario`` per primitive that has at least one
    finding.  Conditions are the union of all finding conditions in each
    group.  Scenarios are sorted by number of satisfied conditions
    (most first).

    Args:
        findings: Classified findings (output of ``classify_findings``).
        protections: Binary protection status (unused directly but
            kept for future extensions).

    Returns:
        List of exploit scenarios sorted by satisfied-condition count.
    """
    groups: dict[ExploitPrimitive, list[Finding]] = {}
    for finding in findings:
        if finding.exploit_primitive == ExploitPrimitive.NONE:
            continue
        groups.setdefault(finding.exploit_primitive, []).append(finding)

    scenarios: list[ExploitScenario] = []
    for primitive, group_findings in groups.items():
        # Aggregate conditions: union by condition name, keep the one
        # that is satisfied if any copy is satisfied.
        merged: dict[str, ExploitCondition] = {}
        for f in group_findings:
            for cond in f.exploit_conditions:
                existing = merged.get(cond.name)
                if existing is None or (cond.satisfied and not existing.satisfied):
                    merged[cond.name] = cond

        title, description = _SCENARIO_INFO.get(
            primitive,
            ("Unknown Scenario", "Unclassified findings."),
        )

        scenarios.append(
            ExploitScenario(
                primitive=primitive,
                title=title,
                description=description,
                conditions=list(merged.values()),
                findings=group_findings,
            )
        )

    scenarios.sort(
        key=lambda s: sum(1 for c in s.conditions if c.satisfied),
        reverse=True,
    )
    return scenarios


# ---------------------------------------------------------------------------
# Condition building
# ---------------------------------------------------------------------------


def _build_conditions(
    imp: DangerousImport,
    call_sites: list[CallSite],
    protections: ProtectionInfo,
) -> list[ExploitCondition]:
    """Build the full list of exploit conditions for a single finding.

    Args:
        imp: The dangerous import being assessed.
        call_sites: Call sites for this import.
        protections: Binary protection flags.

    Returns:
        List of ``ExploitCondition`` objects.
    """
    conditions: list[ExploitCondition] = []

    # Protection-based conditions
    conditions.append(
        ExploitCondition(
            name="no_canary",
            satisfied=not protections.canary,
            confidence=ConditionConfidence.CONFIRMED,
            detail=(
                "Stack canary is absent"
                if not protections.canary
                else "Stack canary is present"
            ),
        )
    )
    conditions.append(
        ExploitCondition(
            name="no_pie",
            satisfied=not protections.pie,
            confidence=ConditionConfidence.CONFIRMED,
            detail="PIE is disabled" if not protections.pie else "PIE is enabled",
        )
    )
    conditions.append(
        ExploitCondition(
            name="no_nx",
            satisfied=not protections.nx,
            confidence=ConditionConfidence.CONFIRMED,
            detail=(
                "NX (non-executable stack) is disabled"
                if not protections.nx
                else "NX is enabled"
            ),
        )
    )
    conditions.append(
        ExploitCondition(
            name="no_relro",
            satisfied=protections.relro == "none",
            confidence=ConditionConfidence.CONFIRMED,
            detail=f"RELRO is {protections.relro}",
        )
    )

    # Argument-based conditions
    has_stack_dest = any(
        arg.register == "rdi" and arg.source == ArgSource.STACK
        for site in call_sites
        for arg in site.arguments
    )
    conditions.append(
        ExploitCondition(
            name="dest_is_stack",
            satisfied=has_stack_dest,
            confidence=(
                ConditionConfidence.CONFIRMED
                if has_stack_dest
                else ConditionConfidence.UNKNOWN
            ),
            detail=(
                "Destination (rdi) points to a stack buffer"
                if has_stack_dest
                else "Destination target unknown"
            ),
        )
    )

    has_input_src = any(
        arg.source == ArgSource.INPUT for site in call_sites for arg in site.arguments
    )
    conditions.append(
        ExploitCondition(
            name="source_is_input",
            satisfied=has_input_src,
            confidence=ConditionConfidence.CONFIRMED,
            detail=(
                "An argument originates from an input source"
                if has_input_src
                else "No input-sourced arguments detected"
            ),
        )
    )

    # Format string condition
    has_fmt_risk = any(site.is_format_string_risk for site in call_sites)
    conditions.append(
        ExploitCondition(
            name="format_string_controlled",
            satisfied=has_fmt_risk,
            confidence=ConditionConfidence.CONFIRMED,
            detail=(
                "Format argument is not a string literal"
                if has_fmt_risk
                else "No format string risk detected"
            ),
        )
    )

    # Category-based conditions
    conditions.append(
        ExploitCondition(
            name="fortified",
            satisfied=imp.category == "mitigated",
            confidence=ConditionConfidence.CONFIRMED,
            detail=(
                "Function is a FORTIFY_SOURCE variant"
                if imp.category == "mitigated"
                else "Function is not fortified"
            ),
        )
    )
    conditions.append(
        ExploitCondition(
            name="critical_function",
            satisfied=imp.category == "critical",
            confidence=ConditionConfidence.CONFIRMED,
            detail=(
                f"{imp.name} is always dangerous (critical category)"
                if imp.category == "critical"
                else f"{imp.name} is in the {imp.category} category"
            ),
        )
    )

    # Call site density
    conditions.append(
        ExploitCondition(
            name="multiple_call_sites",
            satisfied=len(call_sites) >= 3,
            confidence=ConditionConfidence.CONFIRMED,
            detail=(
                f"{len(call_sites)} call sites found"
                if len(call_sites) >= 3
                else f"Only {len(call_sites)} call site(s) found"
            ),
        )
    )

    return conditions


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _compute_severity_score(conditions: list[ExploitCondition]) -> float:
    """Compute the additive severity score from satisfied conditions.

    The score is the sum of weights for each satisfied condition,
    clamped to a minimum of 0.

    Args:
        conditions: List of exploit conditions.

    Returns:
        Non-negative severity score.
    """
    total = 0.0
    for cond in conditions:
        if cond.satisfied:
            total += _CONDITION_WEIGHTS.get(cond.name, 0)
    return max(0.0, total)


# ---------------------------------------------------------------------------
# Primitive determination
# ---------------------------------------------------------------------------


def _determine_primitive(
    conditions: list[ExploitCondition],
    category: str,
) -> ExploitPrimitive:
    """Determine the most likely exploit primitive from conditions.

    Priority order:
    1. ARBITRARY_WRITE — format string + no RELRO
    2. INFO_LEAK — format string controlled
    3. FLOW_CONTROL — critical function or stack dest (not mitigated/fmt)
    4. DOS — fallback when some conditions are satisfied

    Args:
        conditions: List of exploit conditions for the finding.
        category: The import's danger category.

    Returns:
        The determined exploit primitive.
    """
    cond_map = {c.name: c.satisfied for c in conditions}

    fmt_controlled = cond_map.get("format_string_controlled", False)
    no_relro = cond_map.get("no_relro", False)
    critical = cond_map.get("critical_function", False)
    dest_stack = cond_map.get("dest_is_stack", False)

    # ARBITRARY_WRITE: format string + no RELRO
    if fmt_controlled and no_relro:
        return ExploitPrimitive.ARBITRARY_WRITE

    # INFO_LEAK: format string controlled
    if fmt_controlled:
        return ExploitPrimitive.INFO_LEAK

    # FLOW_CONTROL: critical or stack dest, not mitigated or format_string
    if (critical or dest_stack) and category not in ("mitigated", "format_string"):
        return ExploitPrimitive.FLOW_CONTROL

    # DOS: fallback if any condition is satisfied
    if any(c.satisfied for c in conditions):
        return ExploitPrimitive.DOS

    return ExploitPrimitive.NONE


# ---------------------------------------------------------------------------
# Stack layout helpers
# ---------------------------------------------------------------------------


def _find_layout_for_sites(
    call_sites: list[CallSite],
    stack_layouts: dict[str, StackFrameLayout] | None,
) -> StackFrameLayout | None:
    """Find the first matching stack frame layout for a set of call sites.

    Args:
        call_sites: Call sites to search through.
        stack_layouts: Mapping of function name to layout.

    Returns:
        The first matching layout, or ``None``.
    """
    if not stack_layouts:
        return None
    for site in call_sites:
        if site.containing_function in stack_layouts:
            return stack_layouts[site.containing_function]
    return None


def _find_distance_to_return(
    call_sites: list[CallSite],
    stack_layouts: dict[str, StackFrameLayout] | None,
) -> int | None:
    """Estimate the distance from a stack buffer to the return address.

    Searches call sites for one whose destination argument (rdi) points
    to a stack buffer.  If a matching stack frame layout is available,
    uses it to compute the distance.

    Args:
        call_sites: Call sites for the import.
        stack_layouts: Mapping of function name to layout.

    Returns:
        Distance in bytes, or ``None`` if not determinable.
    """
    if not stack_layouts:
        return None

    from elftriage.stackframe import get_slot_for_offset

    for site in call_sites:
        if site.containing_function not in stack_layouts:
            continue
        layout = stack_layouts[site.containing_function]

        for arg in site.arguments:
            if arg.register == "rdi" and arg.source == ArgSource.STACK:
                # Try to parse the offset from the detail string
                offset = _parse_stack_offset(arg.detail)
                if offset is not None:
                    slot = get_slot_for_offset(layout, offset)
                    if slot is not None:
                        dist = estimate_distance_to_return_address(layout, slot)
                        if dist is not None:
                            return dist
    return None


def _parse_stack_offset(detail: str) -> int | None:
    """Parse a stack offset from an argument detail string.

    Handles formats like ``rbp-0x40``, ``rbp - 0x40``, or
    ``rbp-0x40 (64-byte stack buffer)``.

    Args:
        detail: The argument detail string.

    Returns:
        The signed integer offset, or ``None`` if unparsable.
    """
    if not detail:
        return None

    text = detail.split("(")[0].strip().lower()
    if "rbp" not in text:
        return None

    text = text.replace("rbp", "").strip()
    if not text:
        return 0

    # Normalise: "- 0x40" → "-0x40"
    text = text.replace(" ", "")
    try:
        return int(text, 0)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Exploitability notes
# ---------------------------------------------------------------------------


def _generate_exploitability_notes(
    imp: DangerousImport,
    call_sites: list[CallSite],
    protections: ProtectionInfo,
    stack_layout: StackFrameLayout | None = None,
) -> list[str]:
    """Generate context-aware exploitability notes.

    Explains the specific risk of this finding given the binary's
    protections, argument analysis results, and optional stack frame
    layout data.

    Args:
        imp: The dangerous import.
        call_sites: Call sites for this import.
        protections: Binary protection status.
        stack_layout: Optional stack frame layout for the containing
            function, used to add distance-to-return-address notes.

    Returns:
        List of human-readable exploitability notes.
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

    # Stack frame distance note
    if stack_layout is not None and has_stack_dest:
        distance = _compute_distance_from_layout(call_sites, stack_layout)
        if distance is not None:
            notes.append(
                f"Buffer is {distance} bytes from return address "
                "(confirmed via stack frame analysis)"
            )

    # Cross-reference notes
    if has_stack_dest and not protections.canary and imp.category == "critical":
        notes.append(
            "HIGH RISK: stack-targeted write + no canary + critical function "
            "= classic exploitable stack overflow"
        )

    if has_stack_dest and not protections.canary and not protections.pie:
        notes.append(
            "EXPLOIT CHAIN: stack overflow \u2192 overwrite return address "
            "(no canary) \u2192 jump to known address (no PIE)"
        )

    return notes


def _compute_distance_from_layout(
    call_sites: list[CallSite],
    layout: StackFrameLayout,
) -> int | None:
    """Compute distance to return address using a stack frame layout.

    Args:
        call_sites: Call sites to search for stack-dest arguments.
        layout: The stack frame layout of the containing function.

    Returns:
        Distance in bytes, or ``None``.
    """
    from elftriage.stackframe import get_slot_for_offset

    for site in call_sites:
        for arg in site.arguments:
            if arg.register == "rdi" and arg.source == ArgSource.STACK:
                offset = _parse_stack_offset(arg.detail)
                if offset is not None:
                    slot = get_slot_for_offset(layout, offset)
                    if slot is not None:
                        return estimate_distance_to_return_address(layout, slot)
    return None
