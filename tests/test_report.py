"""Tests for report generation."""

import json

from elftriage.report import generate_text_report, generate_json_report
from elftriage.types import (
    AnalysisResult,
    ArgSource,
    ArgumentInfo,
    DangerousImport,
    DisassemblyLine,
    CallSite,
    Finding,
    ProtectionInfo,
)


def _sample_result() -> AnalysisResult:
    """Create a sample analysis result for testing."""
    imp = DangerousImport("gets", "critical", "Always dangerous", 0x4000, 0x6000)
    site = CallSite(
        address=0x8000,
        function_name="gets",
        containing_function="main",
        disassembly_lines=[
            DisassemblyLine(0x7FF0, "mov", "rdi, rbp"),
            DisassemblyLine(0x8000, "call", "0x4000"),
            DisassemblyLine(0x8005, "nop", ""),
        ],
        arguments=[
            ArgumentInfo("rdi", ArgSource.STACK, "rbp-0x40 (64-byte stack buffer)"),
        ],
    )
    finding = Finding(
        dangerous_import=imp,
        call_sites=[site],
        severity_score=15.0,
        exploitability_notes=[
            "gets with no stack canary: overflow can overwrite return address"
        ],
    )
    return AnalysisResult(
        binary_path="/test/binary",
        protections=ProtectionInfo(nx=True, pie=True, canary=False, relro="partial"),
        findings=[finding],
        summary_stats={"total_dangerous_imports": 1, "critical": 1},
    )


def test_text_report_contains_binary_path() -> None:
    """Text report should include the binary path."""
    result = _sample_result()
    report = generate_text_report(result)
    assert "/test/binary" in report


def test_text_report_contains_protections() -> None:
    """Text report should list protection status."""
    result = _sample_result()
    report = generate_text_report(result)
    assert "NX" in report
    assert "PIE" in report
    assert "PARTIAL" in report


def test_text_report_contains_findings() -> None:
    """Text report should include findings."""
    result = _sample_result()
    report = generate_text_report(result)
    assert "gets" in report
    assert "CRITICAL" in report


def test_text_report_contains_exploitability() -> None:
    """Text report should include exploitability notes."""
    result = _sample_result()
    report = generate_text_report(result)
    assert "overflow can overwrite return address" in report


def test_text_report_contains_arguments() -> None:
    """Text report should include argument analysis."""
    result = _sample_result()
    report = generate_text_report(result)
    assert "[rdi]" in report
    assert "stack" in report


def test_text_report_contains_function_name() -> None:
    """Text report should include containing function name."""
    result = _sample_result()
    report = generate_text_report(result)
    assert "in main" in report


def test_text_report_contains_got_address() -> None:
    """Text report should include GOT address."""
    result = _sample_result()
    report = generate_text_report(result)
    assert "GOT address: 0x6000" in report


def test_json_report_is_valid_json() -> None:
    """JSON report should be parseable."""
    result = _sample_result()
    report = generate_json_report(result)
    data = json.loads(report)
    assert data["binary"] == "/test/binary"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["function"] == "gets"


def test_json_report_protections() -> None:
    """JSON report should include protection fields."""
    result = _sample_result()
    data = json.loads(generate_json_report(result))
    prot = data["protections"]
    assert prot["nx"] is True
    assert prot["canary"] is False
    assert prot["relro"] == "partial"


def test_json_report_exploitability_notes() -> None:
    """JSON report should include exploitability notes."""
    result = _sample_result()
    data = json.loads(generate_json_report(result))
    finding = data["findings"][0]
    assert "exploitability_notes" in finding
    assert len(finding["exploitability_notes"]) > 0


def test_json_report_arguments() -> None:
    """JSON report should include argument analysis."""
    result = _sample_result()
    data = json.loads(generate_json_report(result))
    site = data["findings"][0]["call_sites"][0]
    assert "arguments" in site
    assert site["arguments"][0]["register"] == "rdi"
    assert site["arguments"][0]["source"] == "stack"


def test_json_report_got_address() -> None:
    """JSON report should include GOT address."""
    result = _sample_result()
    data = json.loads(generate_json_report(result))
    assert data["findings"][0]["got_address"] == "0x6000"


def test_json_report_containing_function() -> None:
    """JSON report should include containing function name."""
    result = _sample_result()
    data = json.loads(generate_json_report(result))
    site = data["findings"][0]["call_sites"][0]
    assert site["containing_function"] == "main"


def test_empty_findings_report() -> None:
    """Report with no findings should not crash."""
    result = AnalysisResult(binary_path="/test/clean", summary_stats={})
    text = generate_text_report(result)
    assert "No dangerous function imports detected" in text
    data = json.loads(generate_json_report(result))
    assert data["findings"] == []
