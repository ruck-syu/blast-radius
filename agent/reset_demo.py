"""Clear agent-written state for a clean demo: every Decision node (both orgs)
and the action log. Graph data (services, packages, CVEs) is untouched.

  python -m agent.reset_demo
"""
from __future__ import annotations

from mcp_server.actions import action_log_path
from .testkit import decision_ids, delete_decisions


def main() -> None:
    for org in ("dev", "heldout"):
        print(f"{org}: deleted {delete_decisions(org, decision_ids(org))} Decision nodes")
    path = action_log_path()
    if path.exists():
        path.unlink()
        print(f"removed {path}")


if __name__ == "__main__":
    main()
