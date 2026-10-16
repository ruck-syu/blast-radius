"""Test isolation for action-writing tests: a temp action log, and every Decision
node created inside the block is deleted on exit (pre-existing ones are kept).

  with isolated_actions() as log_path:
      ...create_ticket / act / run_agent(allow_actions=True)...
"""
from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from mcp_server import graph


def decision_ids(org: str) -> set[str]:
    rows, _ = graph.run(org, "decision_ids", {})
    return {r[0] for r in rows}


def delete_decisions(org: str, ids: set[str]) -> int:
    if not ids:
        return 0
    rows, _ = graph.run(org, "delete_decisions", {"ids": sorted(ids)})
    return rows[0][0] if rows else 0


@contextmanager
def isolated_actions(orgs: tuple[str, ...] = ("dev", "heldout")):
    before = {org: decision_ids(org) for org in orgs}
    prev = os.environ.get("BLAST_ACTION_LOG")
    with tempfile.TemporaryDirectory() as d:
        log_path = Path(d) / "log.jsonl"
        os.environ["BLAST_ACTION_LOG"] = str(log_path)  # inherited by spawned MCP servers
        try:
            yield log_path
        finally:
            if prev is None:
                os.environ.pop("BLAST_ACTION_LOG", None)
            else:
                os.environ["BLAST_ACTION_LOG"] = prev
            for org in orgs:
                delete_decisions(org, decision_ids(org) - before[org])
