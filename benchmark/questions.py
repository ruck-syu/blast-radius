"""Benchmark question bank (Phase 7).

27 questions per org in 4 groups (1-hop, 2-3 hop, 4-6 hop, counterfactual),
all expected answers derived from planted ground truth
(benchmark/ground_truth.json) plus the seed org files for ownership facts.
No tuning data leaks: thresholds were fixed before any benchmark run.

Usage: python -m benchmark.questions   (writes benchmark/questions/*.json)
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CVES = ["CVE-2021-44228", "CVE-2024-3094", "CVE-2017-5638"]


def build(org: str) -> list[dict]:
    gt = json.loads((ROOT / "benchmark" / "ground_truth.json").read_text())[org]
    seed = json.loads((ROOT / "ingest" / f"seed_{org}.json").read_text())
    aff = {c: gt["cves"][c]["affected"] for c in CVES}
    rch = {c: gt["cves"][c]["reachable"] for c in CVES}
    aff_svc = {c: sorted(a["service"] for a in aff[c]) for c in CVES}
    rch_svc = {c: sorted(x["service"] for x in rch[c]) for c in CVES}
    depth = {(c, a["service"]): a["depth"] for c in CVES for a in aff[c]}
    all_svc = sorted(s["name"] for s in seed["services"])
    clean = sorted(set(all_svc) - {s for v in aff_svc.values() for s in v})
    entries = {x["service"]: sorted(x["entries"]) for c in CVES for x in rch[c]}
    team_of = {}
    for i, s in enumerate(seed["services"]):
        team_of[s["name"]] = seed["teams"][i % len(seed["teams"])]["name"]
    last_dep = {}
    for d in seed["deployments"]:
        s = seed["services"][d["service"]]["name"]
        if s not in last_dep or d["timestamp"] > last_dep[s][1]:
            last_dep[s] = (seed["persons"][d["by"]]["name"], d["timestamp"])
    tier_of = {s["name"]: s["tier"] for s in seed["services"]}
    q: list[dict] = []

    def add(qid: str, group: str, kind: str, text: str, expected: dict, params: dict):
        q.append({"id": f"{org}-{qid}", "org": org, "group": group, "kind": kind,
                  "text": text, "expected": expected, "params": params})

    A, B, C = CVES
    sA, sB = aff_svc[A][0], aff_svc[B][1]

    # ---- 1-hop: single lookups, no traversal ----
    add("01", "1-hop", "scalar", f"Which team owns {sA}?", {"value": team_of[sA]},
        {"service": sA, "field": "team"})
    add("02", "1-hop", "scalar", f"Who last deployed {sA}?", {"value": last_dep[sA][0]},
        {"service": sA, "field": "deployer"})
    add("03", "1-hop", "scalar", f"Is {sA} affected by {A}? yes/no", {"value": "yes"},
        {"cve": A, "service": sA, "field": "affected_yn"})
    add("04", "1-hop", "scalar", f"Is {clean[0]} affected by {A}? yes/no", {"value": "no"},
        {"cve": A, "service": clean[0], "field": "affected_yn"})
    add("05", "1-hop", "scalar", f"How many services does {A} affect?",
        {"value": len(aff_svc[A])}, {"cve": A, "field": "affected_count"})
    add("06", "1-hop", "scalar", f"What tier is {sA}?", {"value": tier_of[sA]},
        {"service": sA, "field": "tier"})

    # ---- 2-3 hop ----
    d3 = sorted(s for s in aff_svc[A] if depth[(A, s)] <= 3)
    add("07", "2-3-hop", "set", f"Services affected by {A} within 3 hops?",
        {"values": d3}, {"cve": A, "field": "affected_maxdepth", "max_depth": 3})
    r0 = rch_svc[A][0]
    add("08", "2-3-hop", "scalar", f"Is {r0} reachable from a public endpoint? yes/no",
        {"value": "yes"}, {"service": r0, "field": "reachable_yn"})
    add("09", "2-3-hop", "set", f"Which entry services expose {r0}?",
        {"values": entries[r0]}, {"service": r0, "field": "entry_services"})
    add("10", "2-3-hop", "scalar", f"Shortest dependency depth from {A} to {sA}?",
        {"value": depth[(A, sA)]}, {"cve": A, "service": sA, "field": "depth"})
    add("11", "2-3-hop", "set", f"Which {A}-affected services are publicly reachable?",
        {"values": rch_svc[A]}, {"cve": A, "field": "reachable_set"})
    t0 = team_of[aff_svc[A][0]]
    t_aff = sorted(s for s in aff_svc[A] if team_of[s] == t0)
    add("12", "2-3-hop", "set", f"{A}-affected services owned by {t0}?",
        {"values": t_aff}, {"cve": A, "field": "team_affected", "team": t0})
    which = sorted(c for c in CVES if sA in aff_svc[c])
    add("13", "2-3-hop", "set", f"Which CVEs affect {sA}?", {"values": which},
        {"service": sA, "field": "cves_for_service"})
    add("14", "2-3-hop", "scalar", f"Dependency depth from {B} to {sB}?",
        {"value": depth[(B, sB)]}, {"cve": B, "service": sB, "field": "depth"})

    # ---- 4-6 hop ----
    add("15", "4-6-hop", "set", f"All services affected by {A}?", {"values": aff_svc[A]},
        {"cve": A, "field": "affected_set"})
    add("16", "4-6-hop", "set", f"All publicly reachable {A}-affected services?",
        {"values": rch_svc[A]}, {"cve": A, "field": "reachable_set"})
    add("17", "4-6-hop", "ranked", f"Top 3 riskiest services for {A}?",
        {"k": 3, "relevant": rch_svc[A]}, {"cve": A, "field": "top_k", "k": 3})
    add("18", "4-6-hop", "ranked", f"Top 5 riskiest services for {A}?",
        {"k": 5, "relevant": rch_svc[A]}, {"cve": A, "field": "top_k", "k": 5})
    mx = max(a["depth"] for a in aff[A])
    deepest = sorted(a["service"] for a in aff[A] if a["depth"] == mx)
    add("19", "4-6-hop", "set", f"Deepest {A}-affected service(s)? (with depth)",
        {"values": deepest, "depth": mx}, {"cve": A, "field": "deepest"})
    union = sorted({s for v in aff_svc.values() for s in v})
    add("20", "4-6-hop", "set", "All affected services across all CVEs?",
        {"values": union}, {"field": "affected_union"})
    deep_svc = deepest[0]
    vuln_purl = next(c["vuln_pkg"]["purl"] for c in seed["cves"] if c["id"] == A)
    add("21", "4-6-hop", "path", f"Proof path from {A} to {deep_svc}?",
        {"start": deep_svc, "end_purl": vuln_purl, "depth": depth[(A, deep_svc)]},
        {"cve": A, "service": deep_svc, "field": "proof_path"})

    # ---- counterfactual ----
    total_reach = sorted({s for v in rch_svc.values() for s in v})
    add("22", "counterfactual", "scalar",
        f"If {A} is fixed, how many reachable affected services remain org-wide?",
        {"value": len(total_reach) - len(rch_svc[A])},
        {"cve": A, "field": "reachable_after_fix"})
    best = gt["best_fix"]["cve"]
    add("23", "counterfactual", "scalar", "Which single fix removes the most reachable services?",
        {"value": best}, {"field": "best_fix"})
    add("24", "counterfactual", "scalar", f"How many reachable services does fixing {A} remove?",
        {"value": len(rch_svc[A])}, {"cve": A, "field": "reachable_removed"})
    only_a = sorted(set(aff_svc[A]) - set(aff_svc[B]))
    add("25", "counterfactual", "set", f"Services affected by {A} but NOT by {B}?",
        {"values": only_a}, {"cve": A, "other": B, "field": "set_difference"})
    add("26", "counterfactual", "scalar",
        f"If {B} is fixed, how many {A}-affected services remain?",
        {"value": len(aff_svc[A])}, {"cve": A, "other": B, "field": "affected_after_other_fix"})
    by_removed = sorted(CVES, key=lambda c: (-len(rch_svc[c]), c))
    add("27", "counterfactual", "ranked", "Rank the 3 CVE fixes by reachable services removed?",
        {"k": 1, "relevant": [best], "full_order": by_removed},
        {"field": "fix_ranking"})
    return q


def main() -> None:
    out_dir = ROOT / "benchmark" / "questions"
    out_dir.mkdir(parents=True, exist_ok=True)
    for org in ("dev", "heldout"):
        qs = build(org)
        (out_dir / f"{org}.json").write_text(json.dumps(qs, indent=2))
        groups = defaultdict(int)
        for x in qs:
            groups[x["group"]] += 1
        print(f"{org}: {len(qs)} questions {dict(groups)} -> {out_dir / f'{org}.json'}")


if __name__ == "__main__":
    main()
