"""assess_change: what would a proposed change do to the org's exposure?

Pre-merge check. GRAPH.COPY the live graph into a private sandbox, apply the
proposed change there (a service starts using packages and/or a new public
endpoint routes to it), then score every CVE on both graphs and diff the
verdicts: what gets worse, and what the change resolves.

Removals mean "the service no longer resolves this purl anywhere in its tree"
(a version pin, or a component gone from its SBOM). The package graph is shared
between services, so removals are not edits: a (CVE, service) pair survives only
if some dependency path avoids every removed purl, and its evidence chain is
that path. The live graph is never touched; the sandbox is always deleted.

New transitive exposure is caught too: adding a package that DEPENDS_ON* a
vulnerable one shows up with the full dependency chain as evidence. Exposure
an added package carries that the service already had (an upgrade target that
is itself vulnerable) is listed separately as `carried`.
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


def _apply_removals(key: str, verdicts: dict, service: str, removed: list[str]) -> None:
    """Drop or re-route `service`'s pairs whose every dependency path hits a removed purl."""
    for cve, svc in [k for k in verdicts if k[1] == service]:
        rows, _ = graph.run_on(key, "dependency_path_avoiding",
                               {"cve": cve, "service": service, "removed": removed})
        if not rows:
            del verdicts[(cve, svc)]
        else:
            verdicts[(cve, svc)].update(path=graph.serialize_path(rows[0][0]), depth=rows[0][1])


def assess_change(service: str, adds: list[str] | None = None, expose_path: str = "",
                  org: str = "dev", removes: list[str] | None = None) -> dict:
    """Diff verdicts before/after `service` adds packages `adds`, drops `removes`,
    and/or gets a public route."""
    t0 = time.time()
    adds, removes = list(adds or []), list(removes or [])
    if not adds and not removes and not expose_path:
        raise ValueError("assess_change: give packages to add/remove and/or an expose_path")
    live = graph_name(org)
    if service not in {r[0] for r in graph.run_on(live, "list_services", {})[0]}:
        raise ValueError(f"assess_change: service {service!r} not in the {org} graph")
    unknown = [p for p in adds
               if not graph.run_on(live, "package_exists", {"purl": p})[0][0][0]]
    known = [p for p in adds if p not in unknown]
    removed = [p for p in removes
               if graph.run_on(live, "service_resolves", {"service": service, "purl": p})[0][0][0]]

    cve_ids = list_cves(live)
    before = _verdicts(live, cve_ids)
    sb = f"{live}__assess_{uuid.uuid4().hex[:8]}"
    graph.connect().select_graph(live).copy(sb)
    try:
        direct, pulled_in = [], []
        for purl in known:
            # already in the tree through an earlier add (a flattened SBOM lists the
            # whole subtree): keep the real transitive chain, don't add a direct edge
            if graph.run_on(sb, "service_resolves",
                            {"service": service, "purl": purl})[0][0][0]:
                pulled_in.append(purl)
                continue
            direct.append(purl)
            graph.run_on(sb, "apply_add_dependency",
                         {"service": service, "purl": purl, "source": "assess"})
        if expose_path:
            graph.run_on(sb, "apply_add_endpoint",
                         {"path": expose_path, "public": True, "service": service,
                          "source": "assess"})
        after = _verdicts(sb, cve_ids)
        if removed:
            _apply_removals(sb, after, service, removed)
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
    # exposure the added packages carry that was already there before the change
    # (not worse, so not a finding): an upgrade target that is itself vulnerable
    added, flagged = set(direct) | set(pulled_in), {(f["cve"], f["service"]) for f in findings}
    carried = [{"cve": cve, "service": svc, "verdict": a["verdict"], "chain": _chain(a["path"])}
               for (cve, svc), a in after.items()
               if svc == service and (cve, svc) not in flagged and added & set(_chain(a["path"]))]
    carried.sort(key=lambda f: (-RANK[f["verdict"]], f["cve"]))
    resolved = []
    for (cve, svc), b in before.items():
        a = after.get((cve, svc))
        if a is None or RANK[a["verdict"]] < RANK[b["verdict"]]:
            resolved.append({"cve": cve, "service": svc, "before": b["verdict"],
                             "after": a["verdict"] if a else None})
    resolved.sort(key=lambda f: (-RANK[f["before"]], f["cve"], f["service"]))
    findings.sort(key=lambda f: (-RANK[f["after"]], -f["risk"]))
    worst = findings[0]["after"] if findings else None
    log.info("assess_change org=%s service=%s adds=%d removes=%d expose=%s findings=%d "
             "resolved=%d", org, service, len(direct), len(removed), bool(expose_path),
             len(findings), len(resolved))
    return {"org": org, "service": service, "adds": direct, "pulled_in": pulled_in,
            "unknown_packages": unknown,
            "removes": removed, "not_used": [p for p in removes if p not in removed],
            "expose_path": expose_path or None, "findings": findings, "worst": worst,
            "resolved": resolved, "carried": carried,
            "cves_checked": len(cve_ids),
            "latency_ms": round((time.time() - t0) * 1000, 1)}
