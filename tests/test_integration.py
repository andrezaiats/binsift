"""End-to-end integration tests."""

import json
import tempfile

from elftriage.cli import analyze, main


def test_full_pipeline_bin_ls(bin_ls_path: str) -> None:
    """Full analysis pipeline against /bin/ls should succeed."""
    result = analyze(bin_ls_path)

    assert result.binary_path == bin_ls_path
    assert result.protections.nx is True
    assert result.summary_stats["total_dangerous_imports"] > 0


def test_cli_text_output(bin_ls_path: str, capsys: object) -> None:
    """CLI should produce text output to stdout."""
    main([bin_ls_path])
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "ELF Vulnerability Triage Report" in captured.out
    assert "Binary Protections" in captured.out


def test_cli_json_output(bin_ls_path: str, capsys: object) -> None:
    """CLI --json should produce valid JSON output."""
    main([bin_ls_path, "--json"])
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    data = json.loads(captured.out)
    assert "findings" in data
    assert "protections" in data


def test_cli_output_to_file(bin_ls_path: str) -> None:
    """CLI --output should write to file."""
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        path = f.name
    main([bin_ls_path, "--output", path])
    with open(path) as f:
        content = f.read()
    assert "ELF Vulnerability Triage Report" in content


def test_invalid_binary_raises(capsys: object) -> None:
    """CLI should exit with error for non-existent binary."""
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        main(["/nonexistent/binary"])
    assert exc_info.value.code == 1


def test_non_elf_file_raises(capsys: object) -> None:
    """CLI should exit with error for non-ELF file."""
    import pytest

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("not an elf file")
        path = f.name
    with pytest.raises(SystemExit) as exc_info:
        main([path])
    assert exc_info.value.code == 1
