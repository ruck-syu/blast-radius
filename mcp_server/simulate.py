"""simulate_fix: sandbox upgrade simulation (Phase 4).

Flow per spec: GRAPH.COPY the live graph into a sandbox graph, apply the fix
in the copy by following the real SUPERSEDED_BY / FIXED_IN upgrade path
(rewire USES + DEPENDS_ON, drop resolved AFFECTS), re-run reachability and
scoring on the copy, return before/after risk, delete the sandbox afterward.
"""
from __future__ import annotations

import logging
import time

from . import graph
from ingest.config import graph_name

log = logging.getLogger("blast-radius.mcp")


def sandbox_key(org: str) -> str:
    return graph_name(org) + "__sandbox"


def list_cves(graph_key: str) -> list[str]:
    rows, _ = graph.run_on(graph_key, "list_cves", {})
    return [r[0] for r in rows]


def summarize(graph_key: str, cve_ids: list[str]) -> dict:
    """Per-CVE affected/reachable/total-risk plus org-wide totals, all in Cypher."""
    per, services, reachable, total = {}, set(), set(), 0.0
    for cve_id in cve_ids:
        rows, _ = graph.run_on(graph_key, "score_risk", {"cve": cve_id})
        aff = {r[0] for r in rows}
        rch = {r[0] for r in rows if r[7]}
        risk = round(sum(r[6] for r in rows), 2)
        per[cve_id] = {"affected": len(aff), "reachable": len(rch), "total_risk": risk}
        services |= aff
        reachable |= rch
        total += risk
    return {"cves": per,
            "totals": {"affected": len(services), "reachable": len(reachable),
                       "total_risk": round(total, 2)}}


def _delete_sandbox(key: str) -> bool:
    try:
        if key not in graph.connect().list_graphs():
            return True
        graph.connect().select_graph(key).delete()
        return True
    except Exception as e:
        log.warning("sandbox delete %s: %s", key, e)
        return False


def simulate_fix(cve: str, fix: str, org: str = "dev") -> dict:
    """Simulate upgrading package `fix` (purl) and re-score. Always cleans up."""
    t0 = time.time()
    live = graph_name(org)
    sb = sandbox_key(org)
    cve_ids = list_cves(live)
    if cve not in cve_ids:
        raise ValueError(f"unknown CVE {cve!r} in {org}")

    before = summarize(live, cve_ids)

    ups, _ = graph.run_on(live, "upgrade_path", {"old_purl": fix})
    if not ups:
        raise ValueError(f"no SUPERSEDED_BY upgrade path for package {fix!r}")
    successor = ups[0][0]
    fixed_cves = sorted(x for x in ups[0][1] if x)

    _delete_sandbox(sb)  # dest must not exist (GRAPH.COPY errors otherwise)
    graph.connect().select_graph(live).copy(sb)
    try:
        params = {"old_purl": fix, "new_purl": successor}
        graph.run_on(sb, "upgrade_uses", params)
        graph.run_on(sb, "upgrade_depends", params)
        graph.run_on(sb, "remove_fixed_affects", params)
        after = summarize(sb, cve_ids)
    finally:
        cleaned = _delete_sandbox(sb)

    b, a = before["totals"], after["totals"]
    bc, ac = before["cves"].get(cve, {}), after["cves"].get(cve, {})
    return {
        "cve": cve, "fix": fix, "successor": successor,
        "fixed_cves": fixed_cves, "org": org,
        "before": before, "after": after,
        "reduction": {
            "total_risk": round(b["total_risk"] - a["total_risk"], 2),
            "reachable": b["reachable"] - a["reachable"],
            "affected": b["affected"] - a["affected"],
            "cve_total_risk": round(bc.get("total_risk", 0) - ac.get("total_risk", 0), 2),
            "cve_reachable": bc.get("reachable", 0) - ac.get("reachable", 0),
            "cve_affected": bc.get("affected", 0) - ac.get("affected", 0),
        },
        "sandbox": sb, "sandbox_cleaned": cleaned,
        "latency_ms": round((time.time() - t0) * 1000, 1),
    }
