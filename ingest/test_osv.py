"""OSV import acceptance, offline: real OSV records saved in ingest/fixtures/
(GHSA-8489-44mv-ggj8 = CVE-2021-44832 log4j, GHSA-cr6j-3jp9-rw65 = CVE-2018-11776
struts), KEV/EPSS given explicitly. Imports are removed at the end.

  python -m ingest.test_osv
"""
from __future__ import annotations

import json
from pathlib import Path

from agent.gate import gate, markdown
from agent.testkit import isolated_actions
from agent.triage import triage
from mcp_server import graph
from mcp_server.actions import open_fix_pr
from mcp_server.simulate import list_cves
from ingest.config import graph_name
from . import osv

FIX = Path(__file__).parent / "fixtures"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@"
STRUTS = "pkg:maven/org.apache.struts/struts2-core@"
fails: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f" ({detail})" if detail else ""))
    if not cond:
        fails.append(name)


def record(name: str) -> dict:
    return json.loads((FIX / f"{name}.json").read_text())


def upgrade_edges() -> int:
    return len(graph.connect().select_graph(graph_name("dev")).query(
        "MATCH ()-[s:SUPERSEDED_BY]->() RETURN s").result_set)


def main() -> None:
    check("CVSS v3 base scores match NVD",
          [osv.cvss3_base(v) for v in ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
                                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                       "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")]
          == [6.6, 10.0, 9.0, 8.1])
    order = ["2.0-beta7", "2.0", "2.0.1", "2.5.10", "2.5.10.1", "2.14.1", "2.17.1"]
    check("version order (qualifiers before release, numeric parts as numbers)",
          sorted(reversed(order), key=osv.vkey) == order)

    p = osv.plan(record("GHSA-8489-44mv-ggj8"), "dev", kev="no", epss=0.5)
    check("plan: CVE id from alias, only the affected version, fix in graph",
          p["cve"] == "CVE-2021-44832" and p["cvss"] == 6.6
          and [a["purl"] for a in p["affects"]] == [LOG4J + "2.14.1"]
          and p["fixes"] == [(LOG4J + "2.14.1", LOG4J + "2.17.1")], str(p["affects"]))

    seeded = {**record("GHSA-8489-44mv-ggj8"), "aliases": ["CVE-2021-44228"]}
    r = osv.write(osv.plan(seeded, "dev", kev="no", epss=0.5))
    check("seeded CVE never overwritten", not r["imported"] and "seeded" in r["reason"])

    cves_before, edges_before = list_cves(graph_name("dev")), upgrade_edges()
    try:
        r = osv.write(p)
        check("import writes the CVE", r["imported"]
              and "CVE-2021-44832" in list_cves(graph_name("dev")))
        new = triage("CVE-2021-44832", "dev", use_llm=False)
        old = triage("CVE-2021-44228", "dev", use_llm=False)
        check("imported CVE triages over the same blast radius (same vulnerable package)",
              {x["service"] for x in new["results"]} == {x["service"] for x in old["results"]}
              and all(x["proof"]["verified"] for x in new["results"]),
              f"{len(new['results'])} services")
        check("not KEV: ACT_NOW only where public reach meets a critical tier",
              all("R_CRITICAL_TIER" in x["rules_fired"] for x in new["results"]
                  if x["verdict"] == "ACT_NOW"))
        check("re-import updates instead of duplicating",
              osv.write(p)["imported"] and len(graph.run("dev", "get_cve",
                                                         {"cve": "CVE-2021-44832"})[0]) == 1)

        s = osv.plan(record("GHSA-cr6j-3jp9-rw65"), "dev", kev="yes", epss=0.9)
        check("struts: both graph versions affected, no fix in graph",
              {a["purl"] for a in s["affects"]} == {STRUTS + "2.3.31", STRUTS + "2.5.10.1"}
              and not s["fixes"] and s["notes"])
        osv.write(s)
        t = triage("CVE-2017-5638", "dev", use_llm=False)
        svc = next(x["service"] for x in t["results"] if x["verdict"] == "ACT_NOW")
        g = gate(svc, [STRUTS + "2.5.10.1"], "", "dev", "ACT_NOW", removes=[STRUTS + "2.3.31"])
        check("gate: upgrade target still carries the imported KEV CVE",
              not g["failed"] and any(c["cve"] == "CVE-2018-11776" for c in g["carried"])
              and "Still exposed through the added packages" in markdown(g), svc)
        row = next(x for x in t["results"] if x["service"] == svc)
        with isolated_actions(("dev",)):
            fx = open_fix_pr("CVE-2017-5638", svc, row["verdict"], "test",
                             row["proof"]["path"], rules=row["rules_fired"])
        check("fix PR accepted (resolves its CVE) but warns the target is still exposed",
              fx["accepted"] and "CVE-2018-11776 (ACT_NOW)" in fx["fix_check"]["still_exposed"]
              and "Warning:" in fx["target"])
    finally:
        r = osv.remove("dev")
    check("remove restores the graph", r["removed"] == 2
          and list_cves(graph_name("dev")) == cves_before and upgrade_edges() == edges_before)

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
