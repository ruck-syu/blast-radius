"""Pre-merge gate acceptance: assess_change finds new exposure in a sandbox copy,
including transitive pulls, passes the fixed version, credits upgrades that resolve
exposure, diffs CycloneDX SBOMs, and never touches the live graph.

  python -m agent.test_gate
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from agent.gate import gate, markdown, sbom_diff
from agent.triage import triage
from agent import live, sbom
from mcp_server import graph
from mcp_server.server import check_reachability, get_cve, mcp

ORG, CVE = "dev", "CVE-2021-44228"
fails: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f" ({detail})" if detail else ""))
    if not cond:
        fails.append(name)


def counts() -> tuple[int, int]:
    g = graph.connect().select_graph("blast_radius_dev")
    return (g.query("MATCH (n) RETURN count(n)").result_set[0][0],
            g.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0])


def main() -> None:
    before = counts()
    meta = get_cve(CVE, ORG)
    t = {r["service"]: r for r in triage(CVE, ORG, use_llm=False)["results"]}
    public_clean = next(s["name"] for s in live.services(ORG) if s["name"] not in t
                        and s["tier"] == "critical"
                        and check_reachability(s["name"], ORG)["reachable"])
    hidden = next(s for s, r in t.items() if not r["reachable"] and r["tier"] == "critical")
    # a package two+ hops above the vulnerable one, used by no service yet
    g = graph.connect().select_graph("blast_radius_dev")
    transitive = g.query(
        "MATCH (x:Package)-[:DEPENDS_ON*2..3]->(:Package {purl: $v}) "
        "RETURN x.purl LIMIT 1", {"v": meta["vuln_purl"]}).result_set[0][0]

    r = gate(public_clean, [transitive], org=ORG)
    f = next((x for x in r["findings"] if x["cve"] == CVE), None)
    check("transitive pull into a public critical service fails the gate",
          r["failed"] and f and f["after"] == "ACT_NOW" and f["before"] is None,
          f"{public_clean} + {transitive}")
    check("finding carries the full dependency chain",
          f and f["chain"][0] == public_clean and f["chain"][1] == transitive
          and f["chain"][-1] == meta["vuln_purl"] and len(f["chain"]) >= 4,
          f and " -> ".join(f["chain"]))

    r = gate(public_clean, [meta["fixed_purl"]], org=ORG)
    check("fixed version passes", not r["failed"] and not any(
        x["cve"] == CVE for x in r["findings"]), meta["fixed_purl"])

    r = gate(hidden, [], expose="/api/gate-test", org=ORG)
    f = next((x for x in r["findings"] if x["cve"] == CVE and x["service"] == hidden), None)
    check("new public route flips SCHEDULE -> ACT_NOW",
          r["failed"] and f and f["before"] == "SCHEDULE" and f["after"] == "ACT_NOW", hidden)
    r2 = gate(hidden, [], expose="/api/gate-test", org=ORG, fail_on="any")
    check("fail-on any also fails", r2["failed"])

    r = gate(public_clean, ["pkg:npm/not-in-graph@0.0.1"], org=ORG)
    check("unknown package reported, not failed",
          r["unknown_packages"] == ["pkg:npm/not-in-graph@0.0.1"] and not r["failed"])
    check("markdown report", "pre-merge check" in markdown(r))
    try:
        gate("no-such-service", [transitive], org=ORG)
        check("unknown service rejected", False)
    except ValueError:
        check("unknown service rejected", True)

    # an upgrade PR: the top ACT_NOW service stops resolving the vulnerable version
    top = next(s for s, r in t.items() if r["verdict"] == "ACT_NOW")
    r = gate(top, [meta["fixed_purl"]], org=ORG, removes=[meta["vuln_purl"]])
    check("upgrade resolves the exposure, no new findings",
          not r["failed"] and not r["findings"] and r["removes"] == [meta["vuln_purl"]]
          and {"cve": CVE, "service": top, "before": "ACT_NOW", "after": None} in r["resolved"],
          top)
    check("resolved listed in the report", "Resolved by this change" in markdown(r))
    r = gate(top, [], org=ORG, removes=["pkg:npm/not-a-dep@1.0.0"])
    check("removing a package the service never resolved changes nothing",
          r["not_used"] == ["pkg:npm/not-a-dep@1.0.0"] and not r["resolved"] and not r["findings"])

    # SBOM diff: base vs PR, flattened (the PR SBOM lists the whole new subtree)
    chain = g.query("MATCH p = (:Package {purl: $x})-[:DEPENDS_ON*]->(:Package {purl: $v}) "
                    "RETURN [n IN nodes(p) | n.purl] LIMIT 1",
                    {"x": transitive, "v": meta["vuln_purl"]}).result_set[0][0]
    with tempfile.TemporaryDirectory() as d:
        base, pr, up = (Path(d) / n for n in ("base.json", "pr.json", "up.json"))
        base.write_text(json.dumps(sbom.export(public_clean, ORG)))
        doc = sbom.export(public_clean, ORG, add=[transitive])
        doc["components"] += [{"type": "library", "purl": p, "bom-ref": p} for p in chain[1:]]
        pr.write_text(json.dumps(doc))
        name, adds, removes = sbom_diff(base, pr)
        check("sbom diff: service from metadata, direct dep first",
              name == public_clean and adds[0] == transitive and set(adds) == set(chain)
              and not removes, f"{adds}")
        r = gate(name, adds, org=ORG, removes=removes)
        f = next((x for x in r["findings"] if x["cve"] == CVE), None)
        check("flattened sbom keeps the transitive chain",
              r["failed"] and r["adds"] == [transitive] and set(r["pulled_in"]) == set(chain[1:])
              and f and f["chain"][1:] == chain, f and " -> ".join(f["chain"]))
        top_base = Path(d) / "top.json"
        top_base.write_text(json.dumps(sbom.export(top, ORG)))
        up.write_text(json.dumps(sbom.export(top, ORG, add=[meta["fixed_purl"]],
                                             drop=[meta["vuln_purl"]])))
        cli = subprocess.run([sys.executable, "-m", "agent.gate", "--sbom-before", str(top_base),
                              "--sbom-after", str(up)], capture_output=True, text=True)
        check("gate CLI on an upgrade SBOM passes and reports the fix",
              cli.returncode == 0 and "resolves" in cli.stdout and top in cli.stdout,
              cli.stdout.splitlines()[0] if cli.stdout else cli.stderr[-200:])
        cli = subprocess.run([sys.executable, "-m", "agent.gate", "--sbom-before", str(base),
                              "--sbom-after", str(pr)], capture_output=True, text=True)
        check("gate CLI on the risky SBOM exits 1", cli.returncode == 1 and "FAIL" in cli.stdout)

    check("live graph untouched", counts() == before, f"{before}")
    left = [k for k in graph.connect().list_graphs() if "__assess" in k]
    check("sandboxes deleted", not left, str(left))
    tools = {t.name for t in asyncio.run(mcp.list_tools())}
    check("assess_change exposed over MCP", "assess_change" in tools)

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
