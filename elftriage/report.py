"""Report generator — produces text and JSON output for analysis results."""

import json
from typing import Any

from elftriage.types import (
    AnalysisResult,
    ArgumentInfo,
    CallSite,
    Finding,
    ProtectionInfo,
)


def generate_text_report(result: AnalysisResult) -> str:
    """Generate a human-readable text report.

    Args:
        result: Complete analysis result.

    Returns:
        Formatted text report string.
    """
    lines: list[str] = []

    lines.append("=" * 70)
    lines.append("ELF Vulnerability Triage Report")
    lines.append("=" * 70)
    lines.append(f"Binary: {result.binary_path}")
    lines.append("")

    # Protections section
    lines.append("-" * 40)
    lines.append("Binary Protections")
    lines.append("-" * 40)
    lines.extend(_format_protections(result.protections))
    lines.append("")

    # Summary
    lines.append("-" * 40)
    lines.append("Summary")
    lines.append("-" * 40)
    for key, value in result.summary_stats.items():
        label = key.replace("_", " ").title()
        lines.append(f"  {label}: {value}")
    if result.functions:
        lines.append(f"  Functions Detected: {len(result.functions)}")
    lines.append("")

    # Findings
    if result.findings:
        lines.append("-" * 40)
        lines.append("Findings (ranked by severity)")
        lines.append("-" * 40)
        for i, finding in enumerate(result.findings, 1):
            lines.extend(_format_finding(i, finding))
            lines.append("")
    else:
        lines.append("No dangerous function imports detected.")

    lines.append("=" * 70)
    return "\n".join(lines)


def generate_json_report(result: AnalysisResult) -> str:
    """Generate a structured JSON report.

    Args:
        result: Complete analysis result.

    Returns:
        JSON string of the analysis result.
    """
    data = _result_to_dict(result)
    return json.dumps(data, indent=2)


def _format_protections(prot: ProtectionInfo) -> list[str]:
    """Format protection info as text lines."""
    return [
        f"  NX (No Execute):           {_yes_no(prot.nx)}",
        f"  PIE (Position Independent): {_yes_no(prot.pie)}",
        f"  Stack Canary:              {_yes_no(prot.canary)}",
        f"  RELRO:                     {prot.relro.upper()}",
        f"  FORTIFY_SOURCE:            {_yes_no(prot.fortify)}",
    ]


def _format_finding(index: int, finding: Finding) -> list[str]:
    """Format a single finding as text lines."""
    imp = finding.dangerous_import
    lines: list[str] = []
    lines.append(f"  [{index}] {imp.name} ({imp.category.upper()})")
    lines.append(f"      Risk: {imp.risk_description}")
    lines.append(f"      PLT address: 0x{imp.plt_address:x}")
    if imp.got_address:
        lines.append(f"      GOT address: 0x{imp.got_address:x}")
    lines.append(f"      Severity score: {finding.severity_score}")
    lines.append(f"      Call sites: {len(finding.call_sites)}")

    # Exploitability notes
    if finding.exploitability_notes:
        lines.append("      Exploitability:")
        for note in finding.exploitability_notes:
            lines.append(f"        ! {note}")

    for site in finding.call_sites:
        header = f"      --- Call at 0x{site.address:x}"
        if site.containing_function:
            header += f" in {site.containing_function}"
        header += " ---"
        lines.append(header)

        # Argument analysis
        if site.arguments:
            for arg in site.arguments:
                source_str = arg.source.value
                detail = f" ({arg.detail})" if arg.detail else ""
                lines.append(f"      [{arg.register}] {source_str}{detail}")

        if site.is_format_string_risk:
            lines.append("      ** FORMAT STRING RISK: format arg is not a literal **")

        for dl in site.disassembly_lines:
            marker = " >>>" if dl.address == site.address else "    "
            lines.append(f"      {marker} 0x{dl.address:x}: {dl.mnemonic} {dl.op_str}")

    return lines


def _yes_no(value: bool) -> str:
    """Convert boolean to Yes/No string."""
    return "Yes" if value else "No"


def _result_to_dict(result: AnalysisResult) -> dict[str, Any]:
    """Convert an AnalysisResult to a JSON-serializable dict."""
    data: dict[str, Any] = {
        "binary": result.binary_path,
        "protections": {
            "nx": result.protections.nx,
            "pie": result.protections.pie,
            "canary": result.protections.canary,
            "relro": result.protections.relro,
            "fortify": result.protections.fortify,
        },
        "findings": [_finding_to_dict(f) for f in result.findings],
        "summary": result.summary_stats,
    }
    if result.functions:
        data["functions_detected"] = len(result.functions)
    return data


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a JSON-serializable dict."""
    imp = finding.dangerous_import
    result: dict[str, Any] = {
        "function": imp.name,
        "category": imp.category,
        "risk_description": imp.risk_description,
        "plt_address": f"0x{imp.plt_address:x}",
        "severity_score": finding.severity_score,
        "call_sites": [_call_site_to_dict(site) for site in finding.call_sites],
    }
    if imp.got_address:
        result["got_address"] = f"0x{imp.got_address:x}"
    if finding.exploitability_notes:
        result["exploitability_notes"] = finding.exploitability_notes
    return result


def _call_site_to_dict(site: CallSite) -> dict[str, Any]:
    """Convert a CallSite to a JSON-serializable dict."""
    data: dict[str, Any] = {
        "address": f"0x{site.address:x}",
        "disassembly": [
            {
                "address": f"0x{dl.address:x}",
                "instruction": f"{dl.mnemonic} {dl.op_str}",
            }
            for dl in site.disassembly_lines
        ],
    }
    if site.containing_function:
        data["containing_function"] = site.containing_function
    if site.arguments:
        data["arguments"] = [_arg_to_dict(arg) for arg in site.arguments]
    if site.is_format_string_risk:
        data["format_string_risk"] = True
    return data


def _arg_to_dict(arg: ArgumentInfo) -> dict[str, str]:
    """Convert an ArgumentInfo to a JSON-serializable dict."""
    result = {
        "register": arg.register,
        "source": arg.source.value,
    }
    if arg.detail:
        result["detail"] = arg.detail
    return result
