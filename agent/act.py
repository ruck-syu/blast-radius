"""Agent act flow (Phase 5): act on triage results, every action backed by a
verified graph proof path. Refusals are returned, never raised.

Usage:
  python -m agent.act CVE-2021-44228 [--org dev] [--verdicts ACT_NOW] [--pr] [--json]
"""
from __future__ import annotations

import argparse
import json

from .triage import triage
from mcp_server.server import create_ticket, notify_owner, open_fix_pr


def act(cve: str, org: str = "dev", verdicts: tuple[str, ...] = ("ACT_NOW",),
        with_pr: bool = False, services: list[str] | None = None) -> dict:
    """Ticket + notify (+ fix PR) for each verified item whose verdict is in `verdicts`,
    optionally limited to `services` (e.g. findings a reviewer approved in the UI)."""
    out = triage(cve, org, use_llm=False)
    if not out["known_cve"]:
        return {"cve": cve, "org": org, "known_cve": False,
                "actions": [], "refusals": [], "summary": out["summary"]}
    actions, refusals = [], []
    for r in out["results"]:
        if r["verdict"] not in verdicts or not r["proof"]["verified"]:
            continue
        if services is not None and r["service"] not in services:
            continue
        proof, rules = r["proof"]["path"], r["rules_fired"]
        calls = [("ticket", create_ticket(cve, r["service"], r["verdict"],
                                          r["explanation"], proof, rules, org)),
                 ("notify", notify_owner(cve, r["service"], r["verdict"],
                                         r["explanation"], proof,
                                         r["owner"]["slack_channel"] or "", rules, org))]
        if with_pr:
            fix = out["cve"].get("fixed_purl", "")
            calls.append(("fix_pr", open_fix_pr(cve, r["service"], r["verdict"],
                                                r["explanation"], proof, fix, rules, org)))
        for kind, res in calls:
            entry = {"kind": kind, "service": r["service"], **res}
            (actions if res["accepted"] else refusals).append(entry)
    return {"cve": cve, "org": org, "known_cve": True, "actions": actions,
            "refusals": refusals,
            "summary": (f"{cve}: {len(actions)} actions accepted, "
                        f"{len(refusals)} refused.")}


def main() -> None:
    ap = argparse.ArgumentParser(description="Act on triage verdicts with proof-backed actions.")
    ap.add_argument("cve")
    ap.add_argument("--org", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--verdicts", default="ACT_NOW",
                    help="comma-separated verdicts to act on")
    ap.add_argument("--pr", action="store_true", help="also open fix PR drafts")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    out = act(args.cve, args.org,
              verdicts=tuple(v.strip() for v in args.verdicts.split(",")),
              with_pr=args.pr)
    if args.json:
        print(json.dumps(out, indent=2))
        return
    print(out["summary"])
    for a in out["actions"]:
        print(f"  + [{a['kind']}] {a['service']} -> {a.get('decision_id')} ({a.get('mode')})")
    for r in out["refusals"]:
        print(f"  ! [{r['kind']}] {r['service']} REFUSED: {r['reason']}")


if __name__ == "__main__":
    main()
