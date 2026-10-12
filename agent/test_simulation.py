"""Phase 4 acceptance: agent compares >=3 candidate fixes and recommends one
with before/after numbers; sandbox cleaned up; live graph untouched.

Validates the recommendation against planted ground truth best_fix on both orgs.

Usage: python -m agent.test_simulation
"""
from __future__ import annotations

import json
from pathlib import Path

from mcp_server.simulate import simulate_fix, sandbox_key
from mcp_server import graph
from agent.compare import compare_fixes

ROOT = Path(__file__).resolve().parent.parent
fails: list[str] = []


def check(label: str, cond: bool, detail: str = ""):
    print(("PASS " if cond else "FAIL ") + label + (f" ({detail})" if detail else ""))
    if not cond:
        fails.append(label)


def live_affected(org: str, cve: str) -> int:
    from ingest.config import graph_name
    rows, _ = graph.run_on(graph_name(org), "score_risk", {"cve": cve})
    return len(rows)


def main() -> None:
    gt = json.loads((ROOT / "benchmark" / "ground_truth.json").read_text())

    for org in ("dev", "heldout"):
        cve = "CVE-2021-44228"
        vuln = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        before_n = live_affected(org, cve)
        r = simulate_fix(cve, vuln, org)
        check(f"{org} fix zeroes CVE affected",
              r["after"]["cves"][cve]["affected"] == 0 and r["before"]["cves"][cve]["affected"] == before_n,
              f"{before_n}=>0")
        check(f"{org} reduction positive",
              r["reduction"]["total_risk"] > 0 and r["reduction"]["reachable"] > 0,
              f"-{r['reduction']['total_risk']:.1f} risk, -{r['reduction']['reachable']} reach")
        check(f"{org} sandbox cleaned",
              r["sandbox_cleaned"] and sandbox_key(org) not in graph.connect().list_graphs())
        check(f"{org} live graph untouched", live_affected(org, cve) == before_n)

        comp = compare_fixes(cve, org)
        check(f"{org} >=3 candidates", len(comp["candidates"]) >= 3,
              str(len(comp["candidates"])))
        check(f"{org} candidates have before/after",
              all(c["before"]["total_risk"] > c["after"]["total_risk"] for c in comp["candidates"]))
        rec = comp["recommendation"]["cve"]
        check(f"{org} recommendation == planted best_fix", rec == gt[org]["best_fix"]["cve"],
              f"recommend={rec} planted={gt[org]['best_fix']['cve']}")

    try:
        simulate_fix("CVE-2021-44228", "pkg:npm/no-such-pkg@9.9.9", "dev")
        check("invalid fix rejected", False)
    except ValueError as e:
        check("invalid fix rejected", True, str(e)[:60])

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
