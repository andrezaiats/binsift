"""Shared data structures for ELF triage analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ConditionConfidence(Enum):
    """Confidence level for an exploitability condition assessment."""

    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class ExploitPrimitive(Enum):
    """Type of exploit primitive a vulnerability may yield."""

    FLOW_CONTROL = "flow_control"
    INFO_LEAK = "info_leak"
    ARBITRARY_WRITE = "arbitrary_write"
    DOS = "dos"
    NONE = "none"


class ArgSource(Enum):
    """Classification of where a function argument originates."""

    STACK = "stack"
    HEAP = "heap"
    RODATA = "rodata"
    INPUT = "input"
    REGISTER = "register"
    UNKNOWN = "unknown"


class Reachability(Enum):
    """Whether a finding is reachable from the program's entry points.

    ``UNKNOWN`` is the default and is also used whenever the call graph
    simply does not contain an edge — absence of evidence is not
    evidence of absence. ``UNREACHABLE`` is reserved for the rare cases
    where there is positive proof the code cannot run (e.g. a symbol
    living in a discarded section).
    """

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
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
    copy_size: Optional[int] = None


@dataclass
class ExploitCondition:
    """A single condition relevant to exploitability assessment.

    Caveats are short structured strings explaining the limits of the
    confidence assessment (e.g. ``"upper bound only"``,
    ``"aliasing not modeled"``, ``"derived from windowed slice"``). They
    let the report carry nuance without overloading the confidence enum
    with extra levels.
    """

    name: str
    satisfied: bool
    confidence: ConditionConfidence
    detail: str = ""
    caveats: list[str] = field(default_factory=list)


@dataclass
class ExploitScenario:
    """A potential exploit scenario linking conditions to a primitive."""

    primitive: ExploitPrimitive
    title: str
    description: str
    conditions: list[ExploitCondition] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Finding:
    """A ranked finding combining a dangerous import with its call sites."""

    dangerous_import: DangerousImport
    call_sites: list[CallSite] = field(default_factory=list)
    severity_score: float = 0.0
    exploitability_notes: list[str] = field(default_factory=list)
    exploit_conditions: list[ExploitCondition] = field(default_factory=list)
    exploit_primitive: ExploitPrimitive = ExploitPrimitive.NONE
    reachability: Reachability = Reachability.UNKNOWN


@dataclass
class FunctionBoundary:
    """A detected function boundary in the binary."""

    name: str
    start_address: int
    end_address: int


@dataclass
class AnalysisResult:
    """Complete analysis result for a binary.

    ``capability_warnings`` collects messages about optional analysis
    features that are unavailable in the current environment (e.g.
    missing call-graph backend or IR taint engine). They are surfaced in
    the report so that two environments analysing the same binary cannot
    silently produce materially different conclusions.
    """

    binary_path: str
    protections: ProtectionInfo = field(default_factory=ProtectionInfo)
    findings: list[Finding] = field(default_factory=list)
    functions: list[FunctionBoundary] = field(default_factory=list)
    summary_stats: dict[str, int] = field(default_factory=dict)
    exploit_scenarios: list[ExploitScenario] = field(default_factory=list)
    capability_warnings: list[str] = field(default_factory=list)
