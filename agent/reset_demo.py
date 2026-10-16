"""Clear demo state: every Decision node and live change (agent.live) in both
orgs, and the action log. Generated graph data is otherwise untouched.

  python -m agent.reset_demo
"""
from __future__ import annotations

from mcp_server.actions import action_log_path
from .live import revert
from .testkit import decision_ids, delete_decisions


def main() -> None:
    for org in ("dev", "heldout"):
        print(f"{org}: deleted {delete_decisions(org, decision_ids(org))} Decision nodes")
        r = revert(org)
        print(f"{org}: reverted {r['endpoints']} live endpoints, {r['dependencies']} live dependencies")
    path = action_log_path()
    if path.exists():
        path.unlink()
        print(f"removed {path}")


if __name__ == "__main__":
    main()
