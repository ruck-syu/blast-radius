"""Graph helper for MCP tools.

- Loads parameterized queries from queries/*.cypher (single source of truth).
- Depth bounds are literals in Cypher; the validated ints are injected here
  (never from untrusted input without validation).
- Serializes FalkorDB Path objects to JSON-safe dicts.
- Measures and logs per-query latency (Phase 2 acceptance criterion).
"""
from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from falkordb import FalkorDB

from ingest.config import (
    HOST, PORT, USERNAME, PASSWORD,
    graph_name, MAX_DEP_DEPTH, MAX_CALL_DEPTH,
)

ROOT = Path(__file__).resolve().parent.parent
QUERIES = ROOT / "queries"

log = logging.getLogger("blast-radius.mcp")

_DEP_RE = re.compile(r"\*0\.\.6")
_CALL_RE = re.compile(r"\*0\.\.4")


def _check_depth(value: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an int, got {value!r}")
    if not 1 <= value <= 10:
        raise ValueError(f"{label} must be 1..10, got {value!r}")
    return value


def load_query(name: str, max_dep_depth: int = MAX_DEP_DEPTH,
               max_call_depth: int = MAX_CALL_DEPTH) -> str:
    """Read queries/<name>.cypher, injecting validated depth bounds."""
    text = (QUERIES / f"{name}.cypher").read_text()
    text = _DEP_RE.sub(f"*0..{_check_depth(max_dep_depth, 'max_dep_depth')}", text)
    text = _CALL_RE.sub(f"*0..{_check_depth(max_call_depth, 'max_call_depth')}", text)
    return text


def connect() -> FalkorDB:
    kwargs = {"host": HOST, "port": PORT}
    if USERNAME:
        kwargs["username"] = USERNAME
    if PASSWORD:
        kwargs["password"] = PASSWORD
    return FalkorDB(**kwargs)


def _node_label(props: dict) -> str:
    for key in ("name", "path", "id", "handle"):
        if key in props and props[key] is not None:
            return f"{props[key]}"
    return "?"


def serialize_path(path) -> dict | None:
    """FalkorDB Path -> JSON-safe {nodes, edges, length, summary}."""
    if path is None:
        return None
    nodes = []
    for n in path.nodes():
        props = dict(n.properties)
        nodes.append({"id": n.id, "labels": list(n.labels), "properties": props})
    edges = []
    for e in path.edges():
        edges.append({"id": e.id, "type": e.relation,
                      "from": e.src_node, "to": e.dest_node,
                      "properties": dict(e.properties)})
    summary = []
    for i, n in enumerate(nodes):
        lab = (n["labels"] or ["?"])[0]
        summary.append(f"{lab}({_node_label(n['properties'])})")
        if i < len(edges):
            summary.append(f"-{edges[i]['type']}->")
    return {"nodes": nodes, "edges": edges,
            "length": len(edges), "summary": " ".join(summary)}


def run_on(graph_key: str, query_name: str, params: dict,
           max_dep_depth: int = MAX_DEP_DEPTH,
           max_call_depth: int = MAX_CALL_DEPTH):
    """Run a .cypher query against an arbitrary graph key (live or sandbox)."""
    cypher = load_query(query_name, max_dep_depth, max_call_depth)
    g = connect().select_graph(graph_key)
    t0 = time.time()
    rs = g.query(cypher, params)
    latency_ms = (time.time() - t0) * 1000
    log.info("query=%s graph=%s latency_ms=%.1f rows=%d",
             query_name, graph_key, latency_ms, len(rs.result_set))
    return rs.result_set, round(latency_ms, 1)


def run(org: str, query_name: str, params: dict,
        max_dep_depth: int = MAX_DEP_DEPTH,
        max_call_depth: int = MAX_CALL_DEPTH):
    """Run a .cypher query against the org's graph. Returns (result_set, latency_ms)."""
    rows, latency_ms = run_on(graph_name(org), query_name, params,
                              max_dep_depth, max_call_depth)
    return rows, latency_ms
