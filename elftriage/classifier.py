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

from elftriage.stackframe import (
    StackFrameLayout,
    estimate_distance_to_return_address,
    get_slot_for_offset,
)
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
    Reachability,
)

# Weights for each condition when computing the additive severity score.
_CONDITION_WEIGHTS: dict[str, float] = {
    "critical_function": 10,
    "no_canary": 8,
    "copy_size_exceeds_buffer": 9,
    "no_nx": 7,
    "dest_is_stack": 7,
    "source_is_input": 6,
    "no_pie": 5,
    "format_string_controlled": 8,
    "no_relro": 3,
    "multiple_call_sites": 2,
    "fortified": -5,
    # Reachability is informational only: satisfied contributes 0.
    # A proved-unreachable penalty is applied directly in
    # ``_compute_severity_score`` (it is never produced by the basic
    # r2-based call graph but is reserved for future analysers).
    "reachable_from_entry": 0,
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
    reachability_by_func: dict[str, Reachability] | None = None,
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
        reachability_by_func: Optional mapping of containing-function
            name to :class:`Reachability`. When ``None``, every finding
            is tagged ``UNKNOWN`` and the reachability condition is
            added with confidence ``UNKNOWN``.

    Returns:
        List of findings sorted by severity score (highest first).
    """
    sites_by_func: dict[str, list[CallSite]] = {}
    for site in call_sites:
        sites_by_func.setdefault(site.function_name, []).append(site)

    findings: list[Finding] = []
    for imp in imports:
        func_sites = sites_by_func.get(imp.name, [])

        # Look up stack frame layout for both conditions and notes.
        layout = _find_layout_for_sites(func_sites, stack_layouts)

        reach = _aggregate_reachability(func_sites, reachability_by_func)

        conditions = _build_conditions(
            imp, func_sites, protections, layout, reach, reachability_by_func is None
        )
        score = _compute_severity_score(conditions)
        primitive = _determine_primitive(conditions, imp.category)

        notes = _generate_exploitability_notes(imp, func_sites, protections, layout)

        findings.append(
            Finding(
                dangerous_import=imp,
                call_sites=func_sites,
                severity_score=score,
                exploitability_notes=notes,
                exploit_conditions=conditions,
                exploit_primitive=primitive,
                reachability=reach,
            )
        )

    findings.sort(key=lambda f: f.severity_score, reverse=True)
    return findings


def _aggregate_reachability(
    call_sites: list[CallSite],
    reachability_by_func: dict[str, Reachability] | None,
) -> Reachability:
    """Pick the best reachability state across a finding's call sites.

    A single ``REACHABLE`` site wins. ``UNREACHABLE`` is only adopted
    when every site with a known state is ``UNREACHABLE``. Missing or
    empty ``reachability_by_func`` maps to ``UNKNOWN``.
    """
    if not reachability_by_func:
        return Reachability.UNKNOWN

    best = Reachability.UNKNOWN
    for site in call_sites:
        state = reachability_by_func.get(site.containing_function)
        if state is None:
            continue
        if state == Reachability.REACHABLE:
            return Reachability.REACHABLE
        if state == Reachability.UNREACHABLE and best == Reachability.UNKNOWN:
            best = Reachability.UNREACHABLE
    return best


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


_SLICE_CAVEATS = ["derived from windowed slice", "aliasing not modeled"]


def _build_conditions(
    imp: DangerousImport,
    call_sites: list[CallSite],
    protections: ProtectionInfo,
    stack_layout: StackFrameLayout | None = None,
    reachability: Reachability = Reachability.UNKNOWN,
    reachability_unavailable: bool = True,
) -> list[ExploitCondition]:
    """Build the full list of exploit conditions for a single finding.

    Conditions whose evidence is structural (read directly from the ELF
    header or symbol tables) are tagged ``CONFIRMED``. Conditions
    derived from the windowed backward slice in :mod:`arganalysis` or
    from the heuristic stack-frame reconstruction are tagged
    ``INFERRED`` and carry explicit caveats.

    Args:
        imp: The dangerous import being assessed.
        call_sites: Call sites for this import.
        protections: Binary protection flags.
        stack_layout: Stack frame layout of the containing function, if
            one was reconstructed.

    Returns:
        List of ``ExploitCondition`` objects.
    """
    conditions: list[ExploitCondition] = []

    # Protection-based conditions — always CONFIRMED.
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

    # Argument-based conditions — INFERRED, derived from the slice.
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
                ConditionConfidence.INFERRED
                if has_stack_dest
                else ConditionConfidence.UNKNOWN
            ),
            detail=(
                "Destination (rdi) points to a stack buffer"
                if has_stack_dest
                else "Destination target unknown"
            ),
            caveats=list(_SLICE_CAVEATS) if has_stack_dest else [],
        )
    )

    has_input_src = any(
        arg.source == ArgSource.INPUT for site in call_sites for arg in site.arguments
    )
    conditions.append(
        ExploitCondition(
            name="source_is_input",
            satisfied=has_input_src,
            confidence=(
                ConditionConfidence.INFERRED
                if has_input_src
                else ConditionConfidence.UNKNOWN
            ),
            detail=(
                "An argument originates from an input source"
                if has_input_src
                else "No input-sourced arguments detected"
            ),
            caveats=list(_SLICE_CAVEATS) if has_input_src else [],
        )
    )

    # Format string condition — INFERRED when source provenance is unclear.
    has_fmt_risk = any(site.is_format_string_risk for site in call_sites)
    fmt_unresolved = any(_fmt_arg_unresolved(site, imp.name) for site in call_sites)
    if has_fmt_risk and fmt_unresolved:
        fmt_confidence = ConditionConfidence.INFERRED
        fmt_caveats = ["format arg source not fully resolved"]
    elif has_fmt_risk:
        fmt_confidence = ConditionConfidence.INFERRED
        fmt_caveats = list(_SLICE_CAVEATS)
    else:
        fmt_confidence = ConditionConfidence.UNKNOWN
        fmt_caveats = []
    conditions.append(
        ExploitCondition(
            name="format_string_controlled",
            satisfied=has_fmt_risk,
            confidence=fmt_confidence,
            detail=(
                "Format argument is not a string literal"
                if has_fmt_risk
                else "No format string risk detected"
            ),
            caveats=fmt_caveats,
        )
    )

    # New: copy_size_exceeds_buffer — the most honest overflow signal.
    conditions.append(_build_copy_size_condition(call_sites, stack_layout))

    # Category-based conditions — CONFIRMED, derived from symbol tables.
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

    # Call site density — CONFIRMED.
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

    # Reachability — tri-state, honest. Absence of a path is UNKNOWN.
    conditions.append(
        _build_reachability_condition(reachability, reachability_unavailable)
    )

    return conditions


def _build_reachability_condition(
    reachability: Reachability,
    unavailable: bool,
) -> ExploitCondition:
    """Build the ``reachable_from_entry`` condition.

    A single condition name is used regardless of the observed state;
    only the ``satisfied`` and ``confidence`` fields change. ``satisfied``
    means "we have evidence the finding is reachable from an entry
    point". When the call graph is unavailable at all, we still emit
    the condition with confidence ``UNKNOWN`` and a caveat so that the
    report makes the capability gap visible per-finding.
    """
    if unavailable:
        return ExploitCondition(
            name="reachable_from_entry",
            satisfied=False,
            confidence=ConditionConfidence.UNKNOWN,
            detail="Call graph unavailable",
            caveats=["install '.[callgraph]' extra and ensure 'r2' on PATH"],
        )

    if reachability == Reachability.REACHABLE:
        return ExploitCondition(
            name="reachable_from_entry",
            satisfied=True,
            confidence=ConditionConfidence.INFERRED,
            detail="Reachable from an entry point via direct calls",
            caveats=[
                "call graph from r2 aaa",
                "may miss indirect calls / callbacks / vtables",
            ],
        )

    if reachability == Reachability.UNREACHABLE:
        # This branch is currently only reached in synthetic tests —
        # see callgraph.py for why basic extraction never emits it.
        return ExploitCondition(
            name="reachable_from_entry",
            satisfied=False,
            confidence=ConditionConfidence.CONFIRMED,
            detail="Proved unreachable (e.g. discarded section)",
        )

    return ExploitCondition(
        name="reachable_from_entry",
        satisfied=False,
        confidence=ConditionConfidence.UNKNOWN,
        detail="No static path found from an entry point",
        caveats=[
            "absence of a call-graph edge is not proof of dead code",
            "indirect calls / callbacks / vtables may still reach this code",
        ],
    )


def _fmt_arg_unresolved(site: CallSite, func_name: str) -> bool:
    """Return True if a site's format argument source could not be resolved.

    Looks up the format-arg index for the function and checks whether
    that argument's source classification was a register pass-through or
    an unknown value — both of which mean the slice could not pin down
    where the format string came from.
    """
    from elftriage import dangerous_functions

    fmt_idx = dangerous_functions.get_format_arg_index(func_name)
    if fmt_idx is None or fmt_idx >= len(site.arguments):
        return False
    fmt_arg = site.arguments[fmt_idx]
    return fmt_arg.source in (ArgSource.REGISTER, ArgSource.UNKNOWN)


def _build_copy_size_condition(
    call_sites: list[CallSite],
    layout: StackFrameLayout | None,
) -> ExploitCondition:
    """Build the ``copy_size_exceeds_buffer`` condition.

    For each call site with a constant ``copy_size`` and a stack
    destination whose containing slot we can locate, compare the copy
    length against the slot's ``size_estimate``. The slot size is the
    distance to the next slot — an upper bound on the buffer's true
    size, not the size itself — so the result is always ``INFERRED``
    with an explicit caveat. ``UNKNOWN`` is used when no comparison can
    be made (no copy_size, no stack dest, or no slot lookup).
    """
    for site in call_sites:
        if site.copy_size is None:
            continue
        slot_offset, _detail = _stack_dest_offset(site)
        if slot_offset is None:
            continue
        if layout is None:
            continue
        slot = get_slot_for_offset(layout, slot_offset)
        if slot is None or slot.size_estimate <= 0:
            continue
        if site.copy_size > slot.size_estimate:
            return ExploitCondition(
                name="copy_size_exceeds_buffer",
                satisfied=True,
                confidence=ConditionConfidence.INFERRED,
                detail=(
                    f"copy length {site.copy_size} > slot size "
                    f"≤{slot.size_estimate} at {slot.offset:+d}"
                ),
                caveats=[
                    "slot size is upper bound (distance to next slot)",
                    "padding and slot reuse not modeled",
                ],
            )

    return ExploitCondition(
        name="copy_size_exceeds_buffer",
        satisfied=False,
        confidence=ConditionConfidence.UNKNOWN,
        detail="No constant copy length and stack destination both visible",
    )


def _stack_dest_offset(site: CallSite) -> tuple[int | None, str]:
    """Pull a stack offset out of an rdi STACK argument's detail string."""
    for arg in site.arguments:
        if arg.register == "rdi" and arg.source == ArgSource.STACK:
            offset = _parse_stack_offset(arg.detail)
            if offset is not None:
                return offset, arg.detail
    return None, ""


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _compute_severity_score(conditions: list[ExploitCondition]) -> float:
    """Compute the additive severity score from satisfied conditions.

    The score is the sum of weights for each satisfied condition,
    clamped to a minimum of 0. A small penalty is applied when the
    reachability condition is *confirmed* unreachable — positive proof
    of dead code — but never for mere absence of a call-graph edge.

    Args:
        conditions: List of exploit conditions.

    Returns:
        Non-negative severity score.
    """
    total = 0.0
    for cond in conditions:
        if cond.satisfied:
            total += _CONDITION_WEIGHTS.get(cond.name, 0)
        elif (
            cond.name == "reachable_from_entry"
            and cond.confidence == ConditionConfidence.CONFIRMED
        ):
            total -= 2
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

    # Stack frame distance note — always an upper bound.
    if stack_layout is not None and has_stack_dest:
        distance = _compute_distance_from_layout(call_sites, stack_layout)
        if distance is not None:
            notes.append(
                f"Buffer is \u2264{distance} bytes from return address "
                "(upper bound from stack layout — padding and slot reuse "
                "not modeled)"
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
    """Compute an upper-bound distance from a stack buffer to the return address.

    The returned value is an upper bound — the buffer is at most this
    many bytes from the saved return address. The slot reconstruction
    cannot prove an exact value without type recovery.
    """
    for site in call_sites:
        for arg in site.arguments:
            if arg.register == "rdi" and arg.source == ArgSource.STACK:
                offset = _parse_stack_offset(arg.detail)
                if offset is not None:
                    slot = get_slot_for_offset(layout, offset)
                    if slot is not None:
                        return estimate_distance_to_return_address(layout, slot)
    return None
