"""org_posture: exposure across every CVE in the org, rolled up two ways.

By service: how many of its (CVE, service) pairs are ACT_NOW / SCHEDULE /
SUPPRESS, total risk, and which CVEs. By vulnerable package: the pairs whose
shortest dependency chain ends at it, the upgrade the graph has for it, and
whether that target version is itself affected by a CVE (an upgrade that
trades one advisory for another). Verdicts use the same rules as triage.
"""
from __future__ import annotations

import time

from . import graph
from .assess import RANK, _verdicts
from .simulate import list_cves
from ingest.config import graph_name


def org_posture(org: str = "dev", limit: int = 10) -> dict:
    t0 = time.time()
    live = graph_name(org)
    cves = list_cves(live)
    pairs = _verdicts(live, cves)

    services: dict[str, dict] = {}
    packages: dict[str, dict] = {}
    for (cve, svc), a in pairs.items():
        s = services.setdefault(svc, {"service": svc, "ACT_NOW": 0, "SCHEDULE": 0,
                                      "SUPPRESS": 0, "risk": 0.0, "cves": []})
        s[a["verdict"]] += 1
        s["risk"] += a["risk"]
        s["cves"].append({"cve": cve, "verdict": a["verdict"], "risk": a["risk"]})
        purl = a["path"]["nodes"][-1]["properties"].get("purl") if a["path"] else None
        if purl:
            p = packages.setdefault(purl, {"purl": purl, "cves": set(), "services": set(),
                                           "ACT_NOW": 0, "risk": 0.0})
            p["cves"].add(cve)
            p["services"].add(svc)
            p["ACT_NOW"] += a["verdict"] == "ACT_NOW"
            p["risk"] += a["risk"]

    for s in services.values():
        s["risk"] = round(s["risk"], 2)
        s["cves"].sort(key=lambda c: (-RANK[c["verdict"]], -c["risk"]))
    pkgs = []
    for p in packages.values():
        up, _ = graph.run(org, "upgrade_path", {"old_purl": p["purl"]})
        target = up[0][0] if up else None
        carried = graph.run(org, "cves_affecting", {"purl": target})[0] if target else []
        pkgs.append({"purl": p["purl"], "cves": sorted(p["cves"]),
                     "services": len(p["services"]), "act_now_pairs": p["ACT_NOW"],
                     "risk": round(p["risk"], 2), "upgrade_to": target,
                     "target_affected_by": [{"cve": c, "in_kev": bool(k), "cvss": v}
                                            for c, k, v in carried]})
    ranked = sorted(services.values(), key=lambda s: (-s["ACT_NOW"], -s["risk"]))
    pkgs.sort(key=lambda p: (-p["act_now_pairs"], -p["risk"]))
    return {"org": org, "cves": len(cves), "pairs": len(pairs),
            "act_now_pairs": sum(s["ACT_NOW"] for s in ranked),
            "services_affected": len(ranked), "services": ranked[:limit],
            "packages": pkgs, "latency_ms": round((time.time() - t0) * 1000, 1)}
