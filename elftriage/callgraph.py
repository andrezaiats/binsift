"""Optional call-graph extraction for reachability analysis.

This module builds a lightweight call graph by delegating to radare2
via ``r2pipe``. Both ``r2`` (the binary) and the ``r2pipe`` Python
package are optional dependencies — if either is missing, the module
exposes ``R2_AVAILABLE = False`` and every public function either
returns ``None`` or reports the absence via the analysis result's
``capability_warnings`` list.

The resulting ``CallGraph`` is used by :mod:`elftriage.classifier` to
mark findings with a three-state :class:`~elftriage.types.Reachability`
tag. Absence of an edge is *never* interpreted as proof that a callee
is dead code — it maps to ``UNKNOWN`` — because basic call-graph
extraction misses indirect calls, dispatch tables, callbacks, vtables,
and .init/.fini arrays.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from typing import Any, Optional

from elftriage.types import Reachability

try:
    import r2pipe  # type: ignore[import-not-found]

    _R2PIPE_IMPORT_OK = True
except ImportError:
    r2pipe = None  # type: ignore[assignment]
    _R2PIPE_IMPORT_OK = False


R2_AVAILABLE: bool = _R2PIPE_IMPORT_OK and shutil.which("r2") is not None


# Canonical entry-point names we treat as roots for the BFS. A function
# is considered reachable if any of these names (or their ``sym.``
# prefixed variants emitted by r2) is an ancestor in the call graph.
_ENTRY_NAMES = {
    "main",
    "entry0",
    "_start",
    "__libc_start_main",
}


CAPABILITY_WARNING = (
    "Reachability analysis unavailable: install with "
    "'pip install -e .[callgraph]' and ensure 'r2' is on PATH "
    "(some findings may include dead-code false positives)"
)


@dataclass
class CallGraph:
    """A directed call graph extracted from a binary.

    Attributes:
        edges: Mapping of caller function name to the set of callee
            names it invokes directly. Both keys and values use the
            bare function name (``sym.foo`` is normalized to ``foo``).
        entry_points: The subset of nodes that are considered roots
            for reachability analysis (main/_start/entry0 variants).
    """

    edges: dict[str, set[str]] = field(default_factory=dict)
    entry_points: set[str] = field(default_factory=set)


def build_call_graph(binary_path: str) -> Optional[CallGraph]:
    """Extract a call graph from *binary_path* using radare2.

    Returns ``None`` if ``r2pipe`` or the ``r2`` binary are unavailable,
    or if the radare2 invocation or JSON parsing fails for any reason.
    Callers should treat ``None`` as "no reachability data available"
    and surface that to the user via ``AnalysisResult.capability_warnings``.

    Args:
        binary_path: Filesystem path to the ELF binary.

    Returns:
        A populated :class:`CallGraph`, or ``None`` on any failure.
    """
    if not R2_AVAILABLE:
        return None

    try:
        pipe = r2pipe.open(binary_path, flags=["-2", "-q"])
    except Exception:
        return None

    try:
        pipe.cmd("aaa")
        raw = pipe.cmd("aflmj")
    finally:
        try:
            pipe.quit()
        except Exception:
            pass

    if not raw:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    return _parse_aflmj(data)


def reachable_from_entry(graph: CallGraph, target: str) -> Reachability:
    """Return the reachability of *target* from the graph's entry roots.

    This is a forward BFS from each name in ``graph.entry_points``; if
    *target* (or its normalized form) is reached, the result is
    ``REACHABLE``. Otherwise the result is ``UNKNOWN`` — absence of a
    path in this shallow call graph is never treated as proof of dead
    code, because indirect calls, callbacks, vtables, and init arrays
    are invisible here.
    """
    target_norm = _normalize(target)
    if not target_norm:
        return Reachability.UNKNOWN

    visited: set[str] = set()
    frontier: list[str] = [e for e in graph.entry_points if e in graph.edges]
    visited.update(frontier)

    if target_norm in visited:
        return Reachability.REACHABLE

    while frontier:
        node = frontier.pop()
        callees = graph.edges.get(node, set())
        for callee in callees:
            if callee == target_norm:
                return Reachability.REACHABLE
            if callee not in visited:
                visited.add(callee)
                frontier.append(callee)

    return Reachability.UNKNOWN


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _parse_aflmj(data: Any) -> CallGraph:
    """Parse r2's ``aflmj`` output into a :class:`CallGraph`.

    ``aflmj`` emits a JSON array where each entry describes a function
    and its outgoing calls via a ``callrefs`` list. Each callref has a
    ``name`` field (when known) and a ``type`` of ``"CALL"`` for direct
    calls. Entries without a ``name`` (raw addresses for unresolved
    indirect calls) are skipped — they can't be tied to a callee name.

    Args:
        data: Parsed JSON from the ``aflmj`` command.

    Returns:
        A populated :class:`CallGraph`. Returns an empty graph if the
        input is not a list.
    """
    graph = CallGraph()
    if not isinstance(data, list):
        return graph

    for entry in data:
        if not isinstance(entry, dict):
            continue
        caller_name = _normalize(entry.get("name", ""))
        if not caller_name:
            continue

        callees: set[str] = graph.edges.setdefault(caller_name, set())

        for ref in entry.get("callrefs", []) or []:
            if not isinstance(ref, dict):
                continue
            if ref.get("type") != "CALL":
                continue
            callee_name = _normalize(ref.get("name", ""))
            if callee_name:
                callees.add(callee_name)

        if caller_name in _ENTRY_NAMES:
            graph.entry_points.add(caller_name)

    # If main wasn't seen, fall back to any entry0/_start present.
    if not graph.entry_points:
        for candidate in ("main", "entry0", "_start"):
            if candidate in graph.edges:
                graph.entry_points.add(candidate)
                break

    return graph


def _normalize(name: str) -> str:
    """Strip common r2 symbol prefixes so lookups work by bare name.

    r2 emits names like ``sym.main``, ``sym.imp.strcpy``, ``fcn.00401130``.
    We keep the final component for matching against :mod:`elftriage`'s
    own function-boundary names, which are bare (``main``, ``strcpy``).
    ``fcn.*`` stub names are returned as-is since they have no bare
    equivalent.
    """
    if not name:
        return ""
    if name.startswith("sym.imp."):
        return name[len("sym.imp.") :]
    if name.startswith("sym."):
        return name[len("sym.") :]
    return name
