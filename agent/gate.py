"""Pre-merge gate: fail a PR whose dependency or routing change opens new exposure.

Runs assess_change (sandbox graph copy, live graph untouched) and prints a
markdown report suitable for a PR comment. Exit 1 when the worst new verdict
reaches --fail-on, else 0.

  python -m agent.gate --service d-search-api --adds pkg:npm/syn-d-pkg-03519@1.19.5
  python -m agent.gate --service d-notify-svc --expose /api/notify/v2 --fail-on SCHEDULE
"""
from __future__ import annotations

import argparse
import json
import sys

from mcp_server.assess import RANK, assess_change
from mcp_server.server import get_cve

FAIL_ON = {"ACT_NOW": 3, "SCHEDULE": 2, "any": 1}


def gate(service: str, adds: list[str], expose: str = "", org: str = "dev",
         fail_on: str = "ACT_NOW") -> dict:
    r = assess_change(service, adds, expose, org)
    r["fail_on"] = fail_on
    r["failed"] = RANK[r["worst"]] >= FAIL_ON[fail_on]
    fixes = {}
    for f in r["findings"]:
        if f["cve"] not in fixes:
            c = get_cve(f["cve"], org)
            fixes[f["cve"]] = {"vulnerable": c.get("vuln_purl"), "fixed": c.get("fixed_purl"),
                               "cvss": c.get("cvss"), "in_kev": c.get("in_kev")}
    r["cve_info"] = fixes
    return r


def markdown(r: dict) -> str:
    change = []
    if r["adds"]:
        change.append(f"`{r['service']}` adds " + ", ".join(f"`{p}`" for p in r["adds"]))
    if r["expose_path"]:
        change.append(f"public endpoint `{r['expose_path']}` routes to `{r['service']}`")
    status = (f"FAIL: new {r['worst']} exposure" if r["failed"]
              else f"PASS (worst new verdict: {r['worst']})" if r["findings"]
              else "PASS: no new exposure")
    out = [f"## Blast Radius pre-merge check: {status}", "",
           f"Change: {'; '.join(change)}.",
           f"Checked {r['cves_checked']} CVEs in a sandbox copy of the {r['org']} graph "
           f"({r['latency_ms']:.0f} ms); fails on {r['fail_on']}.", ""]
    if r["unknown_packages"]:
        out += ["Not in the graph, so not assessed: " +
                ", ".join(f"`{p}`" for p in r["unknown_packages"]), ""]
    if r["findings"]:
        out += ["| CVE | service | verdict | why | dependency chain |",
                "|---|---|---|---|---|"]
        for f in r["findings"]:
            before = f["before"] or "not affected"
            reach = f"public via `{f['entry_point']}`" if f["reachable"] else "no public path"
            out.append(f"| {f['cve']} | `{f['service']}` | {before} → **{f['after']}** | "
                       f"{reach}; {', '.join(f['rules_fired'])} | "
                       + " → ".join(f"`{x}`" for x in f["chain"]) + " |")
        out.append("")
        for cve, c in r["cve_info"].items():
            kev = ", CISA KEV" if c["in_kev"] else ""
            fix = f"fixed in `{c['fixed']}`" if c["fixed"] else "no fixed version in graph"
            out.append(f"- **{cve}** (cvss {c['cvss']}{kev}): `{c['vulnerable']}` is vulnerable; {fix}.")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="pre-merge exposure gate over the FalkorDB graph")
    ap.add_argument("--service", required=True)
    ap.add_argument("--adds", nargs="*", default=[], metavar="PURL")
    ap.add_argument("--expose", default="", metavar="PATH", help="new public endpoint path")
    ap.add_argument("--org", default="dev")
    ap.add_argument("--fail-on", default="ACT_NOW", choices=sorted(FAIL_ON))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not a.adds and not a.expose:
        ap.error("give --adds and/or --expose")
    try:
        r = gate(a.service, a.adds, a.expose, a.org, a.fail_on)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(r, indent=2) if a.json else markdown(r))
    raise SystemExit(1 if r["failed"] else 0)


if __name__ == "__main__":
    main()
