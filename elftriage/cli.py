"""CLI interface for the ELF Vulnerability Triage Tool."""

import argparse
import sys
from typing import Optional

from elftriage.parser import parse_elf
from elftriage.protections import detect_protections
from elftriage.imports import resolve_dangerous_imports
from elftriage.disassembly import disassemble_call_sites
from elftriage.classifier import classify_findings
from elftriage.report import generate_text_report, generate_json_report
from elftriage.types import AnalysisResult


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="elftriage",
        description=(
            "Static analysis triage tool for x86_64 ELF binaries. "
            "Identifies dangerous libc imports, detects binary protections, "
            "and produces a ranked risk report."
        ),
    )
    parser.add_argument(
        "binary",
        help="Path to the ELF binary to analyze",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output report in JSON format",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Write report to file instead of stdout",
    )
    parser.add_argument(
        "--context-lines",
        type=int,
        default=5,
        help="Number of disassembly context lines before/after each call (default: 5)",
    )
    return parser


def analyze(binary_path: str, context_lines: int = 5) -> AnalysisResult:
    """Run the full analysis pipeline on a binary.

    Args:
        binary_path: Path to the ELF binary.
        context_lines: Disassembly context window size.

    Returns:
        Complete analysis result.
    """
    elffile, fh = parse_elf(binary_path)
    try:
        protections = detect_protections(elffile)
        imports = resolve_dangerous_imports(elffile)
        call_sites = disassemble_call_sites(elffile, imports, context_lines)
        findings = classify_findings(imports, call_sites, protections)

        # Build summary stats
        summary: dict[str, int] = {
            "total_dangerous_imports": len(imports),
            "critical": sum(1 for i in imports if i.category == "critical"),
            "warning": sum(1 for i in imports if i.category == "warning"),
            "mitigated": sum(1 for i in imports if i.category == "mitigated"),
            "total_call_sites": len(call_sites),
        }

        return AnalysisResult(
            binary_path=binary_path,
            protections=protections,
            findings=findings,
            summary_stats=summary,
        )
    finally:
        fh.close()


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point for the CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = analyze(args.binary, context_lines=args.context_lines)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.json_output:
        report = generate_json_report(result)
    else:
        report = generate_text_report(result)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
            f.write("\n")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)
