"""apply_change: incremental graph updates with no retraining (demo step 6).

Kinds: add_dependency (service USEs package), add_endpoint (new route),
add_deployment (new deploy record), add_cve (new advisory + optional fix
link). All parameterized upserts from queries/apply_*.cypher; referenced
nodes/packages must already exist (validated, else ValueError).
"""
from __future__ import annotations

import logging
import time

from . import graph

log = logging.getLogger("blast-radius.mcp")


def _req(rows, what: str):
    if not rows:
        raise ValueError(f"apply_change: {what} not found in graph")
    return rows


def apply_change(kind: str, org: str = "dev", service: str = "", purl: str = "",
               path: str = "", public: bool = False, ref_id: str = "",
               version: str = "", by: str = "", timestamp: int = 0,
               cvss: float = 0.0, epss: float = 0.0, summary: str = "",
               published: str = "", affects_purl: str = "", vuln_range: str = "",
               fixed_purl: str = "") -> dict:
    t0 = time.time()
    if kind == "add_dependency":
        rows, lat = graph.run(org, "apply_add_dependency",
                              {"service": service, "purl": purl})
        _req(rows, f"service {service!r} or package {purl!r}")
        detail = {"edge_id": rows[0][0]}
    elif kind == "add_endpoint":
        rows, lat = graph.run(org, "apply_add_endpoint",
                              {"path": path, "public": bool(public), "service": service})
        _req(rows, f"service {service!r}")
        detail = {"endpoint_id": rows[0][0]}
    elif kind == "add_deployment":
        rows, lat = graph.run(org, "apply_add_deployment",
                              {"id": ref_id, "service": service, "version": version,
                               "by": by,
                               "timestamp": timestamp or int(time.time())})
        _req(rows, f"service {service!r} or person {by!r}")
        detail = {"deployment_id": rows[0][0]}
    elif kind == "add_cve":
        rows, lat = graph.run(org, "apply_add_cve",
                              {"id": ref_id, "cvss": float(cvss), "epss": float(epss),
                               "summary": summary, "published": published,
                               "affects_purl": affects_purl, "range": vuln_range})
        _req(rows, f"package {affects_purl!r}")
        detail = {"cve_id": rows[0][0]}
        if fixed_purl:
            rows2, _ = graph.run(org, "apply_add_fix_link",
                                 {"cve": ref_id, "old_purl": affects_purl,
                                  "new_purl": fixed_purl})
            _req(rows2, f"CVE {ref_id!r} or fixed package {fixed_purl!r}")
            detail["fix_linked"] = True
    else:
        raise ValueError(f"apply_change: unknown kind {kind!r} "
                         "(add_dependency|add_endpoint|add_deployment|add_cve)")
    log.info("apply_change kind=%s org=%s", kind, org)
    return {"kind": kind, "org": org, "applied": True, "detail": detail,
            "latency_ms": round((time.time() - t0) * 1000, 1)}
