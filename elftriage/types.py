"""Shared data structures for ELF triage analysis."""

from dataclasses import dataclass, field


@dataclass
class ProtectionInfo:
    """Binary protection status flags."""

    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = "none"  # "none", "partial", "full"
    fortify: bool = False


@dataclass
class DangerousImport:
    """A resolved dangerous libc function import."""

    name: str
    category: str  # "critical", "warning", "mitigated"
    risk_description: str
    plt_address: int


@dataclass
class DisassemblyLine:
    """A single disassembled instruction."""

    address: int
    mnemonic: str
    op_str: str


@dataclass
class CallSite:
    """A call site referencing a dangerous function with surrounding context."""

    address: int
    function_name: str
    disassembly_lines: list[DisassemblyLine] = field(default_factory=list)


@dataclass
class Finding:
    """A ranked finding combining a dangerous import with its call sites."""

    dangerous_import: DangerousImport
    call_sites: list[CallSite] = field(default_factory=list)
    severity_score: float = 0.0


@dataclass
class AnalysisResult:
    """Complete analysis result for a binary."""

    binary_path: str
    protections: ProtectionInfo = field(default_factory=ProtectionInfo)
    findings: list[Finding] = field(default_factory=list)
    summary_stats: dict[str, int] = field(default_factory=dict)
