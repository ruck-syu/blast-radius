"""Phase 4 agent: compare candidate fixes and recommend the best.

Candidates are real upgrade paths: each CVE present in the org graph has a
vulnerable package with a SUPERSEDED_BY successor (see FIXED_IN). The agent
simulates every candidate in a sandbox copy and recommends the largest
org-wide risk reduction (tie-break: most reachable services remediated).
"""
from __future__ import annotations

import logging

from mcp_server.simulate import simulate_fix, list_cves
from mcp_server import graph
from ingest.config import graph_name

log = logging.getLogger("blast-radius.agent")


def compare_fixes(cve: str, org: str = "dev") -> dict:
    """Simulate >=1 fix per CVE in the org; recommend the largest risk reduction."""
    live = graph_name(org)
    cve_ids = list_cves(live)
    if cve not in cve_ids:
        raise ValueError(f"unknown CVE {cve!r} in {org}")

    candidates = []
    for cid in cve_ids:
        rows, _ = graph.run(org, "get_cve", {"cve": cid})
        vuln_purl = rows[0][5]
        sim = simulate_fix(cid, vuln_purl, org)
        candidates.append({
            "cve": cid,
            "fix": vuln_purl,
            "successor": sim["successor"],
            "before": sim["before"]["totals"],
            "after": sim["after"]["totals"],
            "risk_reduction": sim["reduction"]["total_risk"],
            "reachable_removed": sim["reduction"]["reachable"],
            "affected_removed": sim["reduction"]["affected"],
            "latency_ms": sim["latency_ms"],
        })

    # Triaged CVE's own fix first; recommendation by max reduction.
    candidates.sort(key=lambda d: (d["cve"] != cve))
    best = max(candidates,
               key=lambda d: (d["risk_reduction"], d["reachable_removed"]))
    return {
        "triaged_cve": cve, "org": org,
        "candidates": candidates,
        "recommendation": {
            "cve": best["cve"], "fix": best["fix"], "successor": best["successor"],
            "risk_reduction": best["risk_reduction"],
            "reachable_removed": best["reachable_removed"],
            "affected_removed": best["affected_removed"],
            "reason": (f"Upgrading {best['fix']} to {best['successor']} removes "
                       f"{best['risk_reduction']:.2f} total risk and "
                       f"{best['reachable_removed']} reachable affected services, "
                       f"the largest reduction of the {len(candidates)} simulated fixes."),
        },
    }
