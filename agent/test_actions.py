"""Phase 5 acceptance: valid actions succeed (guardrail + Decision node + log),
missing/invalid proofs are refused with logged reasons.

Usage: python -m agent.test_actions
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from mcp_server import graph
from mcp_server.server import score_risk, create_ticket, notify_owner
from agent.act import act

ROOT = Path(__file__).resolve().parent.parent
fails: list[str] = []


def check(label: str, cond: bool, detail: str = ""):
    print(("PASS " if cond else "FAIL ") + label + (f" ({detail})" if detail else ""))
    if not cond:
        fails.append(label)


def decision_links(org: str, did: str):
    rows, _ = graph.run(org, "check_decision", {"id": did})
    return rows


def main() -> None:
    org, cve = "dev", "CVE-2021-44228"
    item = score_risk(cve, org)["ranked"][0]
    svc, proof = item["service"], item["path"]

    # 1. valid ticket -> accepted + Decision node with ABOUT + FIRED links
    r = create_ticket(cve, svc, "ACT_NOW", "acceptance test", proof,
                      ["R_KEV", "R_PUBLIC_REACH"], org)
    check("valid ticket accepted", r["accepted"] and r.get("decision_id"), str(r.get("mode")))
    rows = decision_links(org, r["decision_id"])
    linked = {(row[0], row[1]) for row in rows}
    check("Decision ABOUT CVE+service",
          (cve, "ABOUT") in {(c, t) for c, t, _ in rows} and (svc, "ABOUT") in {(c, t) for c, t, _ in rows},
          str(sorted(linked)[:4]))
    fired = {target for target, t, _ in rows if t == "FIRED"}
    check("Decision FIRED rules", fired == {"R_KEV", "R_PUBLIC_REACH"}, str(sorted(fired)))

    # 2. missing proof -> refused
    r = create_ticket(cve, svc, "ACT_NOW", "x", None, [], org)
    check("missing proof refused", not r["accepted"] and "missing proof_path" in r["reason"])

    # 3. tampered node id -> refused (chain broken)
    bad = copy.deepcopy(proof)
    bad["nodes"][1]["id"] = 999999999
    r = create_ticket(cve, svc, "ACT_NOW", "x", bad, [], org)
    check("tampered proof refused", not r["accepted"] and "broken" in r["reason"],
          r["reason"][:60])

    # 4. forged edge type (consistent ids, no such edge) -> refused (not in graph)
    forged = copy.deepcopy(proof)
    forged["edges"][0]["type"] = "CALLS"
    r = create_ticket(cve, svc, "ACT_NOW", "x", forged, [], org)
    check("forged edge refused", not r["accepted"] and "not in graph" in r["reason"],
          r["reason"][:80])

    # 5. proof for another service -> refused
    r = create_ticket(cve, "d-billing-worker-3", "ACT_NOW", "x", proof, [], org)
    check("wrong-service proof refused", not r["accepted"] and "does not start" in r["reason"])

    # 6. valid notify -> accepted
    r = notify_owner(cve, svc, "ACT_NOW", "acceptance test", proof, "#nebula-d",
                     ["R_KEV"], org)
    check("valid notify accepted", r["accepted"] and r.get("decision_id"))

    # 7. agent act flow: ACT_NOW items get ticket+notify, zero refusals
    out = act(cve, org)
    kinds = {}
    for a in out["actions"]:
        kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
    check("agent acted on ACT_NOW", kinds.get("ticket", 0) == 6 and kinds.get("notify", 0) == 6,
          f"{kinds}, {out['summary']}")
    check("agent zero refusals", out["refusals"] == [])

    # 8. action log has accepts + refusals
    log_lines = (ROOT / "actions" / "log.jsonl").read_text().strip().split("\n")
    entries = [json.loads(line) for line in log_lines]
    check("action log accepts+refusals",
          any(e["accepted"] for e in entries) and any(not e["accepted"] for e in entries),
          f"{len(entries)} entries")

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
