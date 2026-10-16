"""Pre-merge gate: fail a PR whose dependency or routing change opens new exposure.

Runs assess_change (sandbox graph copy, live graph untouched) and prints a
markdown report suitable for a PR comment: new exposure the change opens, and
exposure it resolves. Exit 1 when the worst new verdict reaches --fail-on, else 0.

The change comes from explicit purls, or from two CycloneDX SBOMs (the base
branch and the PR branch): components only in the PR SBOM are adds, components
only in the base SBOM are removes (the service no longer resolves them).

  python -m agent.gate --service d-search-api --adds pkg:npm/syn-d-pkg-03519@1.19.5
  python -m agent.gate --service d-notify-svc --expose /api/notify/v2 --fail-on SCHEDULE
  python -m agent.gate --sbom-before base.cdx.json --sbom-after pr.cdx.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_server.assess import RANK, assess_change
from mcp_server.server import get_cve

FAIL_ON = {"ACT_NOW": 3, "SCHEDULE": 2, "any": 1}


def read_sbom(path: str | Path) -> tuple[str | None, set[str], set[str]]:
    """CycloneDX JSON -> (metadata.component.name, all component purls, direct purls).
    Direct = the root's dependsOn in `dependencies`, when the SBOM records it."""
    doc = json.loads(Path(path).read_text())
    if doc.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path}: not a CycloneDX JSON SBOM")
    root = doc.get("metadata", {}).get("component", {})
    purls, refs = set(), {}
    stack = list(doc.get("components", []))
    while stack:
        c = stack.pop()
        if c.get("purl"):
            purls.add(c["purl"])
            refs[c.get("bom-ref", c["purl"])] = c["purl"]
        stack.extend(c.get("components", []))
    direct = {refs[r] for d in doc.get("dependencies", [])
              if d.get("ref") == root.get("bom-ref") for r in d.get("dependsOn", []) if r in refs}
    return root.get("name"), purls, direct


def sbom_diff(before: str | Path, after: str | Path) -> tuple[str | None, list[str], list[str]]:
    """(service, adds, removes) between a base-branch SBOM and a PR-branch SBOM.
    New direct dependencies come first so assess_change keeps their transitive
    subtree as chains instead of treating every new component as direct."""
    name_b, b, _ = read_sbom(before)
    name_a, a, direct = read_sbom(after)
    new = a - b
    return (name_a or name_b, sorted(new & direct) + sorted(new - direct), sorted(b - a))


def gate(service: str, adds: list[str], expose: str = "", org: str = "dev",
         fail_on: str = "ACT_NOW", removes: list[str] | None = None) -> dict:
    r = assess_change(service, adds, expose, org, removes)
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
    if r["pulled_in"]:
        change.append(f"{len(r['pulled_in'])} more already in their dependency tree")
    if r["removes"]:
        change.append(f"`{r['service']}` no longer resolves "
                      + ", ".join(f"`{p}`" for p in r["removes"]))
    if r["expose_path"]:
        change.append(f"public endpoint `{r['expose_path']}` routes to `{r['service']}`")
    fixed = f", resolves {len(r['resolved'])}" if r["resolved"] else ""
    status = (f"FAIL: new {r['worst']} exposure{fixed}" if r["failed"]
              else f"PASS (worst new verdict: {r['worst']}{fixed})" if r["findings"]
              else f"PASS: no new exposure{fixed}")
    out = [f"## Blast Radius pre-merge check: {status}", "",
           f"Change: {'; '.join(change) or 'no assessable change'}.",
           f"Checked {r['cves_checked']} CVEs in a sandbox copy of the {r['org']} graph "
           f"({r['latency_ms']:.0f} ms); fails on {r['fail_on']}.", ""]
    if r["unknown_packages"]:
        out += ["Not in the graph, so not assessed: " +
                ", ".join(f"`{p}`" for p in r["unknown_packages"]), ""]
    if r["not_used"]:
        out += [f"Removed but not in `{r['service']}`'s dependency tree in the graph: " +
                ", ".join(f"`{p}`" for p in r["not_used"]), ""]
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
        out.append("")
    if r["resolved"]:
        out += ["Resolved by this change:", ""]
        for f in r["resolved"]:
            after = f"now {f['after']}" if f["after"] else "no longer affected"
            out.append(f"- {f['cve']} on `{f['service']}`: was {f['before']}, {after}")
        out.append("")
    if r.get("carried"):
        out += ["Still exposed through the added packages (already the case before this change):", ""]
        for f in r["carried"]:
            out.append(f"- {f['cve']} on `{f['service']}`: {f['verdict']} via "
                       + " → ".join(f"`{x}`" for x in f["chain"]))
    return "\n".join(out).rstrip() + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="pre-merge exposure gate over the FalkorDB graph")
    ap.add_argument("--service", help="defaults to the SBOM's metadata.component.name")
    ap.add_argument("--adds", nargs="*", default=[], metavar="PURL")
    ap.add_argument("--removes", nargs="*", default=[], metavar="PURL",
                    help="purls the service will no longer resolve")
    ap.add_argument("--sbom-before", metavar="CDX_JSON", help="CycloneDX SBOM of the base branch")
    ap.add_argument("--sbom-after", metavar="CDX_JSON", help="CycloneDX SBOM of the PR branch")
    ap.add_argument("--expose", default="", metavar="PATH", help="new public endpoint path")
    ap.add_argument("--org", default="dev")
    ap.add_argument("--fail-on", default="ACT_NOW", choices=sorted(FAIL_ON))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    service, adds, removes = a.service, list(a.adds), list(a.removes)
    if bool(a.sbom_before) != bool(a.sbom_after):
        ap.error("give both --sbom-before and --sbom-after")
    try:
        if a.sbom_before:
            name, sb_adds, sb_removes = sbom_diff(a.sbom_before, a.sbom_after)
            service = service or name
            adds += sb_adds
            removes += sb_removes
        if not service:
            ap.error("give --service (or SBOMs with metadata.component.name)")
        if not adds and not removes and not a.expose:
            print(f"## Blast Radius pre-merge check: PASS: no dependency or routing change "
                  f"for `{service}`")
            raise SystemExit(0)
        r = gate(service, adds, a.expose, a.org, a.fail_on, removes)
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(r, indent=2) if a.json else markdown(r))
    raise SystemExit(1 if r["failed"] else 0)


if __name__ == "__main__":
    main()
