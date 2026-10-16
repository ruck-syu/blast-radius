"""Phase 3 acceptance: a CVE input produces a ranked, explained result end to end.

Checks per CVE: affected set == planted ground truth, every proof path
verified, verdicts consistent (reachable+KEV -> ACT_NOW), explanations/owners
present, unknown CVE handled.

Usage: python -m agent.test_agent
"""
from __future__ import annotations

import json
from pathlib import Path

from .triage import triage

ROOT = Path(__file__).resolve().parent.parent
fails: list[str] = []


def check(label: str, cond: bool, detail: str = ""):
    print(("PASS " if cond else "FAIL ") + label + (f" ({detail})" if detail else ""))
    if not cond:
        fails.append(label)


def check_cve(cve_id: str, org: str, truth: dict):
    out = triage(cve_id, org, use_llm=False)
    check(f"{org} {cve_id} known", out["known_cve"])
    expected = {a["service"] for a in truth["cves"][cve_id]["affected"]}
    got = {r["service"] for r in out["results"]}
    check(f"{org} {cve_id} affected exact", got == expected, f"n={len(got)}")
    check(f"{org} {cve_id} all proofs verified",
          all(r["proof"]["verified"] for r in out["results"]),
          f"{out['total_latency_ms']}ms {len(out['plan'])} calls")
    exp_reach = {x["service"] for x in truth["cves"][cve_id]["reachable"]}
    act_now = {r["service"] for r in out["results"] if r["verdict"] == "ACT_NOW"}
    check(f"{org} {cve_id} ACT_NOW == reachable", act_now == exp_reach,
          f"act_now={len(act_now)} reach={len(exp_reach)}")
    check(f"{org} {cve_id} public routes verified for reachable, none otherwise",
          all((r["exposure"] or {}).get("verified") if r["reachable"] else r["exposure"] is None
              for r in out["results"]))
    risks = [r["risk"] for r in out["results"]]
    check(f"{org} {cve_id} ranked desc", all(a >= b for a, b in zip(risks, risks[1:])))
    check(f"{org} {cve_id} explanations+owners+rules",
          all(r["explanation"] and r["owner"]["team"] and r["rules_fired"] for r in out["results"]))
    check(f"{org} {cve_id} summary", bool(out["summary"]) and cve_id in out["summary"])


def main() -> None:
    gt = json.loads((ROOT / "benchmark" / "ground_truth.json").read_text())
    for cve_id in gt["dev"]["cves"]:
        check_cve(cve_id, "dev", gt["dev"])
    check_cve("CVE-2021-44228", "heldout", gt["heldout"])

    out = triage("CVE-2099-00000", "dev", use_llm=False)
    check("unknown CVE handled",
          out["known_cve"] is False and out["results"] == [], out["summary"])

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
