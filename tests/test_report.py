"""Tests for report generation."""

import json

from elftriage.report import generate_text_report, generate_json_report
from elftriage.types import (
    AnalysisResult,
    DangerousImport,
    DisassemblyLine,
    CallSite,
    Finding,
    ProtectionInfo,
)


def _sample_result() -> AnalysisResult:
    """Create a sample analysis result for testing."""
    imp = DangerousImport("gets", "critical", "Always dangerous", 0x4000)
    site = CallSite(
        address=0x8000,
        function_name="gets",
        disassembly_lines=[
            DisassemblyLine(0x7FF0, "mov", "rdi, rbp"),
            DisassemblyLine(0x8000, "call", "0x4000"),
            DisassemblyLine(0x8005, "nop", ""),
        ],
    )
    finding = Finding(dangerous_import=imp, call_sites=[site], severity_score=15.0)
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


def test_empty_findings_report() -> None:
    """Report with no findings should not crash."""
    result = AnalysisResult(binary_path="/test/clean", summary_stats={})
    text = generate_text_report(result)
    assert "No dangerous function imports detected" in text
    data = json.loads(generate_json_report(result))
    assert data["findings"] == []
