"""Phase 1 acceptance: find_affected_services returns correct results for >=3 known CVEs.

Compares the Cypher query in queries/find_affected_services.cypher against
planted ground truth (benchmark/ground_truth.json) on the dev graph.
Reports per-CVE precision/recall + query latency.

Usage: python -m ingest.verify [--org dev]
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from falkordb import FalkorDB

from .config import HOST, PORT, USERNAME, PASSWORD, graph_name, MAX_DEP_DEPTH

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", default="dev", choices=["dev", "heldout"])
    args = ap.parse_args()

    kwargs = {"host": HOST, "port": PORT}
    if USERNAME:
        kwargs["username"] = USERNAME
    if PASSWORD:
        kwargs["password"] = PASSWORD
    g = FalkorDB(**kwargs).select_graph(graph_name(args.org))

    cypher = (ROOT / "queries" / "find_affected_services.cypher").read_text()
    truth = json.loads((ROOT / "benchmark" / "ground_truth.json").read_text())[args.org]

    all_ok = True
    for cve_id, info in truth["cves"].items():
        expected = {a["service"] for a in info["affected"]}
        t0 = time.time()
        rs = g.query(cypher, {"cve": cve_id})
        dt_ms = (time.time() - t0) * 1000
        got = {row[0] for row in rs.result_set}
        tp = got & expected
        prec = len(tp) / len(got) if got else 0.0
        rec = len(tp) / len(expected) if expected else 1.0
        status = "OK " if prec == 1.0 and rec == 1.0 else "FAIL"
        if status == "FAIL":
            all_ok = False
            print(f"  missing: {sorted(expected - got)[:5]}  extra: {sorted(got - expected)[:5]}")
        print(f"[{status}] {cve_id}: expected={len(expected)} got={len(got)} "
              f"P={prec:.3f} R={rec:.3f} {dt_ms:.0f}ms (max_depth={MAX_DEP_DEPTH})")

    print("ACCEPTANCE PASS: 3/3 CVEs correct" if all_ok else "ACCEPTANCE FAIL")
    raise SystemExit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
