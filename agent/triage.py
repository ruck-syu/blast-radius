"""Phase 3 agent: CVE ID -> ranked, explained triage with a proof path per item.

Plan (deterministic; LLM used only for the final summary wording):
  1. get_cve      - CVE metadata + vulnerable/fixed purls (unknown-CVE guard)
  2. score_risk   - ranked affected services with risk components + paths
  3. per service: evaluate_rules + find_owner
  4. verify each proof path (chain integrity + endpoints match CVE/service)
  5. verdict per item from fired rules; template explanation (LLM override if configured)

The agent never writes free-form Cypher: every traversal is a parameterized
query from queries/*.cypher, invoked through the same functions the MCP
server exposes (mcp_server/server.py serves them over stdio for external clients).

Usage:
  python -m agent.triage CVE-2021-44228 [--org dev] [--json] [--no-llm]
"""
from __future__ import annotations

import argparse
import json
import logging
import time

from mcp_server.server import get_cve as server_get_cve
from mcp_server.server import (
    find_affected_services, check_reachability, dependency_path,
    rank_criticality, find_owner, score_risk, evaluate_rules,
)
from . import llm

log = logging.getLogger("blast-radius.agent")

VERDICTS = ("ACT_NOW", "SCHEDULE", "SUPPRESS")


def verdict_for(fired: list[str]) -> tuple[str, str]:
    """Deterministic verdict from fired rules (thresholds in DECISIONS.md)."""
    has = set(fired)
    if "R_PUBLIC_REACH" in has and ("R_KEV" in has or "R_CRITICAL_TIER" in has):
        return "ACT_NOW", "reachable from a public endpoint and KEV-listed or critical tier"
    if "R_NO_REACH" in has and "R_KEV" not in has:
        return "SUPPRESS", "no public path and not KEV-listed"
    return "SCHEDULE", "affected but below the act-now bar"


def verify_proof(path: dict | None, service: str, vuln_purl: str) -> tuple[bool, str]:
    """Check a serialized proof path: chain integrity + expected endpoints."""
    if not path or not path.get("nodes") or not path.get("edges"):
        return False, "empty path"
    nodes, edges = path["nodes"], path["edges"]
    ids = [n["id"] for n in nodes]
    for i, e in enumerate(edges):
        if e["from"] != ids[i] or e["to"] != ids[i + 1]:
            return False, f"broken chain at edge {i}"
    first, last = nodes[0], nodes[-1]
    if first["labels"] != ["Service"] or first["properties"].get("name") != service:
        return False, "path does not start at the service"
    if "Package" not in last["labels"] or last["properties"].get("purl") != vuln_purl:
        return False, "path does not end at the CVE's vulnerable package"
    types = [e["type"] for e in edges]
    if types[0] != "USES" or any(t != "DEPENDS_ON" for t in types[1:]):
        return False, f"unexpected edge types {types}"
    return True, "chain verified from service to vulnerable package"


def get_cve(cve: str, org: str) -> dict | None:
    meta = server_get_cve(cve, org)
    if not meta["found"]:
        return None
    return {k: v for k, v in meta.items() if k not in ("org", "found")}


def triage(cve_id: str, org: str = "dev", use_llm: bool = True) -> dict:
    t0 = time.time()
    plan: list[dict] = []

    def step(tool: str, result: dict) -> dict:
        plan.append({"tool": tool, "latency_ms": result.get("latency_ms")})
        return result

    meta = get_cve(cve_id, org)
    if meta is None:
        return {"cve": cve_id, "org": org, "known_cve": False,
                "results": [], "summary": f"{cve_id} is not present in the {org} graph.",
                "plan": plan, "total_latency_ms": round((time.time() - t0) * 1000, 1)}

    scored = step("score_risk", score_risk(cve_id, org))
    results = []
    for item in scored["ranked"]:
        svc = item["service"]
        rules = step("evaluate_rules", evaluate_rules(cve_id, svc, org))
        owner = step("find_owner", find_owner(svc, org))
        fired = rules["fired"]
        ok, reason = verify_proof(item["path"], svc, meta["vuln_purl"])
        verdict, why = verdict_for(fired)
        entry = f"reachable from public {item['entry_point']}" if item["reachable"] else "no public path"
        explanation = (
            f"{svc} ({item['tier']}) is {item['depth']} hops from {meta['vuln_purl']} "
            f"({entry}); risk {item['risk']:.1f} = {item['severity']:.2f}x"
            f"{item['exposure']:.1f}x{item['criticality']:.2f} -> {verdict} "
            f"({why}; fired: {', '.join(fired)}). Owner {owner.get('team')} "
            f"({owner.get('slack_channel')}), last deployed by {owner.get('last_deployer')}.")
        results.append({
            "service": svc, "tier": item["tier"], "depth": item["depth"],
            "risk": item["risk"],
            "components": {"severity": round(item["severity"], 3),
                           "exposure": item["exposure"],
                           "criticality": round(item["criticality"], 3)},
            "reachable": item["reachable"], "entry_point": item["entry_point"],
            "verdict": verdict, "verdict_reason": why, "rules_fired": fired,
            "owner": {"team": owner.get("team"), "slack_channel": owner.get("slack_channel"),
                      "last_deployer": owner.get("last_deployer"),
                      "deployed_at": owner.get("deployed_at")},
            "proof": {"path": item["path"], "verified": ok, "detail": reason},
            "explanation": explanation,
        })

    n_act = sum(1 for r in results if r["verdict"] == "ACT_NOW")
    top = results[0]["service"] if results else "-"
    summary = (f"{cve_id} ({meta['summary']}) affects {len(results)} services in {org}, "
               f"{sum(1 for r in results if r['reachable'])} reachable from public endpoints. "
               f"Top risk: {top}. Verdicts: {n_act} ACT_NOW, "
               f"{sum(1 for r in results if r['verdict'] == 'SCHEDULE')} SCHEDULE, "
               f"{sum(1 for r in results if r['verdict'] == 'SUPPRESS')} SUPPRESS.")
    llm_used = "template"
    if use_llm and results:
        prompt = ("Write a 3-sentence incident-triage summary for a security engineer. "
                  f"Facts: {summary} Per-service detail: " +
                  "; ".join(r["explanation"] for r in results[:5]))
        custom = llm.summarize(prompt)
        if custom:
            summary = custom
            llm_used = "llm"

    return {"cve": meta, "org": org, "known_cve": True, "results": results,
            "summary": summary, "plan": plan, "llm": llm_used,
            "total_latency_ms": round((time.time() - t0) * 1000, 1)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Triage a CVE to a ranked, explained service list.")
    ap.add_argument("cve", help="CVE ID, e.g. CVE-2021-44228")
    ap.add_argument("--org", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--json", action="store_true", help="print full JSON instead of text")
    ap.add_argument("--no-llm", action="store_true", help="skip LLM summary even if configured")
    ap.add_argument("--compare-fixes", action="store_true",
                    help="simulate a fix per CVE and recommend the best (Phase 4)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING)
    out = triage(args.cve, args.org, use_llm=not args.no_llm)
    if args.compare_fixes and out["known_cve"]:
        from .compare import compare_fixes
        out["fix_comparison"] = compare_fixes(args.cve, args.org)
    if args.json:
        print(json.dumps(out, indent=2))
        return
    if not out["known_cve"]:
        print(out["summary"])
        return
    print(out["summary"])
    print(f"({len(out['plan'])} tool calls, {out['total_latency_ms']:.0f}ms, summary via {out['llm']})")
    for r in out["results"]:
        mark = "OK " if r["proof"]["verified"] else "BAD"
        print(f"[{r['verdict']:9s}][{mark}] {r['risk']:6.2f} {r['service']} "
              f"depth={r['depth']} rules={','.join(r['rules_fired'])}")
        print(f"           {r['explanation']}")
    if out.get("fix_comparison"):
        print("\nFix comparison (simulated in sandbox copies):")
        for c in out["fix_comparison"]["candidates"]:
            print(f"  {c['cve']}: upgrade {c['fix'].split('@')[0]} -> "
                  f"risk {c['before']['total_risk']:.1f}=>{c['after']['total_risk']:.1f} "
                  f"(-{c['risk_reduction']:.1f}), reachable "
                  f"{c['before']['reachable']}=>{c['after']['reachable']}")
        rec = out["fix_comparison"]["recommendation"]
        print(f"  RECOMMEND {rec['cve']}: {rec['reason']}")


if __name__ == "__main__":
    main()
