"""Tests for the optional call-graph extraction module."""

from __future__ import annotations

import pytest

from elftriage.callgraph import (
    CAPABILITY_WARNING,
    CallGraph,
    R2_AVAILABLE,
    _normalize,
    _parse_aflmj,
    build_call_graph,
    reachable_from_entry,
)
from elftriage.types import Reachability


# ---------------------------------------------------------------------------
# Pure-unit tests (no r2 required)
# ---------------------------------------------------------------------------


def test_normalize_strips_sym_prefix() -> None:
    assert _normalize("sym.main") == "main"
    assert _normalize("sym.imp.strcpy") == "strcpy"
    assert _normalize("dbg.vulnerable_function") == "vulnerable_function"
    assert _normalize("reloc.__libc_start_main") == "__libc_start_main"
    assert _normalize("main") == "main"
    assert _normalize("") == ""


def test_parse_aflmj_empty_list() -> None:
    graph = _parse_aflmj([])
    assert isinstance(graph, CallGraph)
    assert graph.edges == {}
    assert graph.entry_points == set()


def test_parse_aflmj_builds_edges_and_entry_points() -> None:
    """A typical aflmj blob produces a graph with normalized names."""
    data = [
        {
            "name": "sym.main",
            "callrefs": [
                {"type": "CALL", "name": "sym.vulnerable_function"},
                {"type": "CALL", "name": "sym.imp.puts"},
                {"type": "DATA", "name": "sym.imp.stderr"},
            ],
        },
        {
            "name": "sym.vulnerable_function",
            "callrefs": [
                {"type": "CALL", "name": "sym.imp.strcpy"},
                {"type": "CALL", "name": "sym.imp.gets"},
            ],
        },
        {
            "name": "sym.unreachable_helper",
            "callrefs": [{"type": "CALL", "name": "sym.imp.memcpy"}],
        },
    ]
    graph = _parse_aflmj(data)

    assert "main" in graph.entry_points
    assert graph.edges["main"] == {"vulnerable_function", "puts"}
    assert graph.edges["vulnerable_function"] == {"strcpy", "gets"}
    assert graph.edges["unreachable_helper"] == {"memcpy"}


def test_parse_aflmj_modern_schema_with_calls_field() -> None:
    """Modern r2 emits a `calls` array (no `type`); the parser handles both."""
    data = [
        {
            "name": "dbg.main",
            "calls": [
                {"name": "dbg.vulnerable_function"},
                {"name": "sym.imp.printf"},
            ],
        },
        {
            "name": "dbg.vulnerable_function",
            "calls": [{"name": "sym.imp.strcpy"}],
        },
    ]
    graph = _parse_aflmj(data)
    assert graph.edges["main"] == {"vulnerable_function", "printf"}
    assert graph.edges["vulnerable_function"] == {"strcpy"}
    assert "main" in graph.entry_points


def test_parse_aflmj_ignores_nameless_refs() -> None:
    """Calls without a name (raw indirect calls) are skipped."""
    data = [
        {
            "name": "sym.main",
            "calls": [
                {"name": ""},
                {},  # missing name
                {"name": "sym.imp.strcpy"},
            ],
        }
    ]
    graph = _parse_aflmj(data)
    assert graph.edges["main"] == {"strcpy"}


def test_parse_aflmj_falls_back_to_entry0() -> None:
    """If main isn't present, entry0 is adopted as the BFS root."""
    data = [
        {
            "name": "entry0",
            "callrefs": [{"type": "CALL", "name": "sym.libc_csu_init"}],
        }
    ]
    graph = _parse_aflmj(data)
    assert "entry0" in graph.entry_points


def test_reachable_from_entry_direct_edge() -> None:
    graph = CallGraph(
        edges={"main": {"vulnerable_function"}, "vulnerable_function": set()},
        entry_points={"main"},
    )
    assert reachable_from_entry(graph, "vulnerable_function") == Reachability.REACHABLE


def test_reachable_from_entry_transitive() -> None:
    graph = CallGraph(
        edges={
            "main": {"vulnerable_function"},
            "vulnerable_function": {"strcpy"},
            "strcpy": set(),
        },
        entry_points={"main"},
    )
    assert reachable_from_entry(graph, "strcpy") == Reachability.REACHABLE


def test_reachable_from_entry_missing_edge_is_unknown() -> None:
    """Absence of a path is UNKNOWN, never UNREACHABLE."""
    graph = CallGraph(
        edges={"main": {"foo"}, "foo": set(), "orphan_helper": {"strcpy"}},
        entry_points={"main"},
    )
    assert reachable_from_entry(graph, "orphan_helper") == Reachability.UNKNOWN
    assert reachable_from_entry(graph, "strcpy") == Reachability.UNKNOWN


def test_reachable_from_entry_with_sym_prefix() -> None:
    """The BFS normalizes target names with sym. prefixes."""
    graph = CallGraph(
        edges={"main": {"vulnerable_function"}, "vulnerable_function": set()},
        entry_points={"main"},
    )
    assert (
        reachable_from_entry(graph, "sym.vulnerable_function") == Reachability.REACHABLE
    )


def test_capability_warning_mentions_installation() -> None:
    """The warning message must tell users exactly how to fix it."""
    assert "pip install" in CAPABILITY_WARNING
    assert "callgraph" in CAPABILITY_WARNING
    assert "r2" in CAPABILITY_WARNING


# ---------------------------------------------------------------------------
# Integration: only runs when r2/r2pipe are actually installed
# ---------------------------------------------------------------------------


def test_build_call_graph_returns_none_when_unavailable() -> None:
    """When the optional backend is missing, build_call_graph returns None."""
    if R2_AVAILABLE:
        pytest.skip("r2 is available; None-on-absence path is not exercised")
    assert build_call_graph("/bin/ls") is None


@pytest.mark.skipif(not R2_AVAILABLE, reason="r2/r2pipe not installed")
def test_build_call_graph_on_ls() -> None:
    """With r2 available, /bin/ls yields a non-trivial call graph."""
    graph = build_call_graph("/bin/ls")
    assert graph is not None
    assert len(graph.edges) > 0
    # At least one of the canonical entry points should be present.
    assert graph.entry_points
