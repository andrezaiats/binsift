"""Shared data structures for ELF triage analysis."""

from dataclasses import dataclass, field
from enum import Enum


class ArgSource(Enum):
    """Classification of where a function argument originates."""

    STACK = "stack"
    HEAP = "heap"
    RODATA = "rodata"
    INPUT = "input"
    REGISTER = "register"
    UNKNOWN = "unknown"


@dataclass
class ProtectionInfo:
    """Binary protection status flags."""

    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = "none"  # "none", "partial", "full"
    fortify: bool = False


@dataclass
class ArgumentInfo:
    """Analysis of a single function argument at a call site."""

    register: str  # e.g. "rdi", "rsi", "rdx"
    source: ArgSource = ArgSource.UNKNOWN
    detail: str = ""  # e.g. "rbp-0x40 (64-byte stack buffer)"


@dataclass
class DangerousImport:
    """A resolved dangerous libc function import."""

    name: str
    category: str  # "critical", "warning", "mitigated", "format_string"
    risk_description: str
    plt_address: int
    got_address: int = 0


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
    containing_function: str = ""
    disassembly_lines: list[DisassemblyLine] = field(default_factory=list)
    arguments: list[ArgumentInfo] = field(default_factory=list)
    is_format_string_risk: bool = False


@dataclass
class Finding:
    """A ranked finding combining a dangerous import with its call sites."""

    dangerous_import: DangerousImport
    call_sites: list[CallSite] = field(default_factory=list)
    severity_score: float = 0.0
    exploitability_notes: list[str] = field(default_factory=list)


@dataclass
class FunctionBoundary:
    """A detected function boundary in the binary."""

    name: str
    start_address: int
    end_address: int


@dataclass
class AnalysisResult:
    """Complete analysis result for a binary."""

    binary_path: str
    protections: ProtectionInfo = field(default_factory=ProtectionInfo)
    findings: list[Finding] = field(default_factory=list)
    functions: list[FunctionBoundary] = field(default_factory=list)
    summary_stats: dict[str, int] = field(default_factory=dict)
