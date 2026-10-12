"""apply_change test: incremental updates take effect immediately and revert cleanly.

Covers add_dependency (clean service becomes affected), add_endpoint (public
route changes reachability), add_deployment (newest deployer changes),
add_cve (new advisory triages), unknown-kind and dangling-reference rejection.
Every mutation is reverted; the live graph is identical afterward.

Usage: python -m mcp_server.test_apply
"""
from __future__ import annotations

from mcp_server import graph
from mcp_server.server import (
    apply_change, find_affected_services, check_reachability, find_owner, score_risk,
)

ORG = "dev"
fails: list[str] = []


def check(label: str, cond: bool, detail: str = ""):
    print(("PASS " if cond else "FAIL ") + label + (f" ({detail})" if detail else ""))
    if not cond:
        fails.append(label)


def cypher(q: str, params: dict | None = None):
    return graph.connect().select_graph("blast_radius_dev").query(q, params or {})


def main() -> None:
    cve = "CVE-2021-44228"
    vuln = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    before = {s["service"] for s in find_affected_services(cve, ORG)["services"]}

    # clean service (unaffected by anything) gains the vulnerable dependency
    candidates = ["d-cache-warmer", "d-search-api", "d-user-profile"]
    clean = next(s for s in candidates
                 if not any(find_affected_services(c, ORG)["services"] and
                            s in {x["service"] for x in find_affected_services(c, ORG)["services"]}
                            for c in ("CVE-2021-44228", "CVE-2024-3094", "CVE-2017-5638")))
    r = apply_change("add_dependency", ORG, service=clean, purl=vuln)
    check("add_dependency applied", r["applied"])
    after = {s["service"] for s in find_affected_services(cve, ORG)["services"]}
    check("clean service now affected", after == before | {clean}, f"+{clean}")
    cypher("MATCH (s:Service {name:$s})-[r:USES]->(:Package {purl:$p}) DELETE r",
           {"s": clean, "p": vuln})
    check("dependency reverted",
          {s["service"] for s in find_affected_services(cve, ORG)["services"]} == before)

    # new public endpoint to an unreachable affected service changes reachability
    unreach = next(s for s in find_affected_services(cve, ORG)["services"]
                   if not check_reachability(s["service"], ORG)["reachable"])["service"]
    r = apply_change("add_endpoint", ORG, path="/api/d/v1/test-route", public=True, service=unreach)
    check("add_endpoint applied", r["applied"])
    check("service now reachable", check_reachability(unreach, ORG)["reachable"])
    cypher("MATCH (e:Endpoint {path:'/api/d/v1/test-route'}) DETACH DELETE e")
    check("endpoint reverted", not check_reachability(unreach, ORG)["reachable"])

    # new deployment changes the most-recent deployer
    owner_before = find_owner(clean, ORG)["last_deployer"]
    r = apply_change("add_deployment", ORG, ref_id="d-test-dep-1", service=clean,
                     version="v9.9.9", by="@adalark", timestamp=1999999999)
    check("add_deployment applied", r["applied"])
    check("deployer updated", find_owner(clean, ORG)["last_deployer"] == "Ada Lark",
          f"{owner_before} -> Ada Lark")
    cypher("MATCH (d:Deployment {id:'d-test-dep-1'}) DETACH DELETE d")
    check("deployment reverted", find_owner(clean, ORG)["last_deployer"] == owner_before)

    # new CVE triages immediately with no retraining
    r = apply_change("add_cve", ORG, ref_id="CVE-2099-TEST1", cvss=9.0,
                     summary="synthetic test advisory", published="2026-01-01",
                     affects_purl=vuln, vuln_range="<9.9")
    check("add_cve applied", r["applied"])
    n = len(score_risk("CVE-2099-TEST1", ORG)["ranked"])
    check("new CVE triages", n == len(before), f"{n} affected")
    cypher("MATCH (c:CVE {id:'CVE-2099-TEST1'}) DETACH DELETE c")
    check("CVE reverted", score_risk("CVE-2099-TEST1", ORG)["count"] == 0)

    # rejections
    try:
        apply_change("add_frobnicator", ORG)
        check("unknown kind rejected", False)
    except ValueError:
        check("unknown kind rejected", True)
    try:
        apply_change("add_dependency", ORG, service="no-such-svc", purl=vuln)
        check("dangling reference rejected", False)
    except ValueError:
        check("dangling reference rejected", True)

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
