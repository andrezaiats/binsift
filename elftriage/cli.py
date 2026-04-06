"""CLI interface for the ELF Vulnerability Triage Tool."""

import argparse
import sys
from typing import Optional, Sequence

from elftriage.parser import open_elf
from elftriage.protections import detect_protections
from elftriage.imports import resolve_dangerous_imports
from elftriage.disassembly import disassemble_call_sites
from elftriage.functions import detect_functions
from elftriage.arganalysis import analyze_call_arguments
from elftriage.classifier import classify_findings, build_exploit_scenarios
from elftriage.stackframe import StackFrameLayout, analyze_stack_frame
from elftriage.report import generate_text_report, generate_json_report
from elftriage.types import AnalysisResult, FunctionBoundary


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

    Pipeline stages:
    1. Parse and validate the ELF binary.
    2. Detect binary protections (NX, PIE, canary, RELRO, FORTIFY).
    3. Resolve dangerous imports via PLT/GOT.
    4. Detect function boundaries.
    5. Disassemble call sites with context.
    6. Analyze argument provenance at each call site.
    7. Classify and rank findings with exploitability notes.

    Args:
        binary_path: Path to the ELF binary.
        context_lines: Disassembly context window size.

    Returns:
        Complete analysis result.
    """
    with open_elf(binary_path) as elffile:
        protections = detect_protections(elffile)
        imports = resolve_dangerous_imports(elffile)
        functions = detect_functions(elffile)
        call_sites = disassemble_call_sites(elffile, imports, context_lines, functions)
        call_sites = analyze_call_arguments(elffile, call_sites)

        # Build stack frame layouts for functions containing call sites
        stack_layouts = _build_stack_layouts(elffile, call_sites, functions)

        findings = classify_findings(imports, call_sites, protections, stack_layouts)
        scenarios = build_exploit_scenarios(findings, protections)

        # Build summary stats
        summary: dict[str, int] = {
            "total_dangerous_imports": len(imports),
            "critical": sum(1 for i in imports if i.category == "critical"),
            "warning": sum(1 for i in imports if i.category == "warning"),
            "format_string": sum(1 for i in imports if i.category == "format_string"),
            "mitigated": sum(1 for i in imports if i.category == "mitigated"),
            "total_call_sites": len(call_sites),
            "format_string_risks": sum(
                1 for s in call_sites if s.is_format_string_risk
            ),
        }

        return AnalysisResult(
            binary_path=binary_path,
            protections=protections,
            findings=findings,
            functions=functions,
            summary_stats=summary,
            exploit_scenarios=scenarios,
        )


def _build_stack_layouts(
    elffile: object,
    call_sites: Sequence[object],
    functions: list[FunctionBoundary],
) -> dict[str, StackFrameLayout]:
    """Build stack frame layouts for functions that contain call sites.

    Only analyzes functions that are referenced by at least one call site,
    avoiding unnecessary disassembly of the entire binary.

    Args:
        elffile: A parsed ELF file object.
        call_sites: List of call sites with containing_function set.
        functions: List of detected function boundaries.

    Returns:
        Mapping of function name to its reconstructed stack frame layout.
    """
    # Collect unique function names referenced by call sites
    target_names: set[str] = set()
    for site in call_sites:
        if hasattr(site, "containing_function") and site.containing_function:
            target_names.add(site.containing_function)

    if not target_names:
        return {}

    # Build a lookup from function name to boundary
    func_by_name: dict[str, FunctionBoundary] = {f.name: f for f in functions}

    layouts: dict[str, StackFrameLayout] = {}
    for name in target_names:
        func = func_by_name.get(name)
        if func is not None:
            layouts[name] = analyze_stack_frame(elffile, func)  # type: ignore[arg-type]

    return layouts


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
