"""assess_change: what would a proposed change do to the org's exposure?

Pre-merge check. GRAPH.COPY the live graph into a private sandbox, apply the
proposed change there (a service starts using packages, and/or a new public
endpoint routes to it), then score every CVE on both graphs and diff the
verdicts. The live graph is never touched; the sandbox is always deleted.

New transitive exposure is caught too: adding a package that DEPENDS_ON* a
vulnerable one shows up with the full dependency chain as evidence.
"""
from __future__ import annotations

import logging
import time
import uuid

from . import graph
from .simulate import _delete_sandbox, list_cves
from ingest.config import graph_name

log = logging.getLogger("blast-radius.mcp")

RANK = {None: 0, "SUPPRESS": 1, "SCHEDULE": 2, "ACT_NOW": 3}


def _verdict(fired: set[str]) -> str:
    # Same thresholds as agent.triage.verdict_for (kept local: mcp_server must not import agent).
    if "R_PUBLIC_REACH" in fired and ("R_KEV" in fired or "R_CRITICAL_TIER" in fired):
        return "ACT_NOW"
    if "R_NO_REACH" in fired and "R_KEV" not in fired:
        return "SUPPRESS"
    return "SCHEDULE"


def _verdicts(key: str, cve_ids: list[str]) -> dict[tuple[str, str], dict]:
    """(cve, service) -> verdict, rules, depth, reachability, dependency path."""
    out = {}
    for cve in cve_ids:
        rows, _ = graph.run_on(key, "score_risk", {"cve": cve})
        for r in rows:
            rules, _ = graph.run_on(key, "evaluate_rules", {"cve": cve, "service": r[0]})
            fired = sorted(x[0] for x in rules if x[2])
            out[(cve, r[0])] = {"verdict": _verdict(set(fired)), "rules_fired": fired,
                                "depth": r[2], "risk": round(r[6], 2),
                                "reachable": bool(r[7]), "entry_point": r[8],
                                "path": graph.serialize_path(r[9])}
    return out


def _chain(path: dict | None) -> list[str]:
    if not path:
        return []
    return [n["properties"].get("purl") or n["properties"].get("name") or "?"
            for n in path["nodes"]]


def assess_change(service: str, adds: list[str] | None = None, expose_path: str = "",
                  org: str = "dev") -> dict:
    """Diff verdicts before/after `service` adds packages `adds` and/or gets a public route."""
    t0 = time.time()
    adds = list(adds or [])
    if not adds and not expose_path:
        raise ValueError("assess_change: give packages to add and/or an expose_path")
    live = graph_name(org)
    if service not in {r[0] for r in graph.run_on(live, "list_services", {})[0]}:
        raise ValueError(f"assess_change: service {service!r} not in the {org} graph")
    unknown = [p for p in adds
               if not graph.run_on(live, "package_exists", {"purl": p})[0][0][0]]
    known = [p for p in adds if p not in unknown]

    cve_ids = list_cves(live)
    before = _verdicts(live, cve_ids)
    sb = f"{live}__assess_{uuid.uuid4().hex[:8]}"
    graph.connect().select_graph(live).copy(sb)
    try:
        for purl in known:
            graph.run_on(sb, "apply_add_dependency",
                         {"service": service, "purl": purl, "source": "assess"})
        if expose_path:
            graph.run_on(sb, "apply_add_endpoint",
                         {"path": expose_path, "public": True, "service": service,
                          "source": "assess"})
        after = _verdicts(sb, cve_ids)
    finally:
        _delete_sandbox(sb)

    findings = []
    for (cve, svc), a in after.items():
        b = before.get((cve, svc))
        b_verdict = b["verdict"] if b else None
        worse = RANK[a["verdict"]] > RANK[b_verdict]
        newly_reachable = a["reachable"] and not (b and b["reachable"])
        if not (worse or newly_reachable):
            continue
        findings.append({"cve": cve, "service": svc, "before": b_verdict,
                         "after": a["verdict"], "rules_fired": a["rules_fired"],
                         "reachable": a["reachable"], "entry_point": a["entry_point"],
                         "depth": a["depth"], "risk": a["risk"],
                         "chain": _chain(a["path"]),
                         "new_exposure": b is None})
    findings.sort(key=lambda f: (-RANK[f["after"]], -f["risk"]))
    worst = findings[0]["after"] if findings else None
    log.info("assess_change org=%s service=%s adds=%d expose=%s findings=%d",
             org, service, len(known), bool(expose_path), len(findings))
    return {"org": org, "service": service, "adds": known, "unknown_packages": unknown,
            "expose_path": expose_path or None, "findings": findings, "worst": worst,
            "cves_checked": len(cve_ids),
            "latency_ms": round((time.time() - t0) * 1000, 1)}
