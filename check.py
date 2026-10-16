"""Run every acceptance suite against the loaded FalkorDB graphs and report one line each.

  python check.py           # all suites, ~1-2 min
  python check.py gate ui   # only suites whose module name contains one of the words
"""
from __future__ import annotations

import subprocess
import sys
import time

SUITES = [
    "mcp_server.test_tools", "agent.test_agent", "agent.test_simulation",
    "agent.test_actions", "mcp_server.test_apply", "agent.test_mcp_agent",
    "agent.test_gate", "ingest.test_osv", "ui.test_ui",
]


def main() -> None:
    picked = [s for s in SUITES if not sys.argv[1:] or any(w in s for w in sys.argv[1:])]
    failed = []
    for mod in picked:
        t0 = time.monotonic()
        r = subprocess.run([sys.executable, "-m", mod], capture_output=True, text=True)
        ok = r.returncode == 0
        print(f"{'PASS' if ok else 'FAIL'}  {mod:<26} {time.monotonic() - t0:5.1f}s")
        if not ok:
            failed.append(mod)
            tail = (r.stdout + r.stderr).strip().splitlines()[-15:]
            print("\n".join("      " + line for line in tail))
    print(f"{len(picked) - len(failed)}/{len(picked)} suites pass")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
