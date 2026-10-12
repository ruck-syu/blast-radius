"""Benchmark runner (Phase 7): three systems, identical questions, shared metrics.

Metrics per spec: scalar correctness, set precision/recall, ranked
precision@k + MRR, path endpoint accuracy + path validity rate (fraction of
cited paths whose every edge exists in the graph), latency, call counts.

  python -m benchmark.runner --org all [--writer proxy|llm] [--ablate]
  python -m benchmark.runner --org heldout   # final numbers live here

--ablate disables the graph layer and runs the agent only: every
graph-dependent capability must report unknown (~0), proving the product
does not work without FalkorDB.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "benchmark" / "results"


def validate_path(org: str, ids: list[int] | None, rels: list[str] | None,
                  service: str, cve: str) -> dict:
    """Shared path validator reusing the guardrail queries."""
    from mcp_server import graph
    if not ids or len(ids) < 2 or not rels or len(rels) != len(ids) - 1:
        return {"cited": False, "valid": False}
    for i, rel in enumerate(rels):
        rows, _ = graph.run(org, "verify_edge",
                            {"src": ids[i], "dst": ids[i + 1], "rel": rel})
        if not rows[0][0]:
            return {"cited": True, "valid": False}
    rows, _ = graph.run(org, "verify_path_start", {"service": service, "nid": ids[0]})
    if not rows[0][0]:
        return {"cited": True, "valid": False}
    rows, _ = graph.run(org, "verify_path_cve_anchor", {"cve": cve, "nid": ids[-1]})
    return {"cited": True, "valid": bool(rows[0][0])}


def norm(v) -> str:
    return str(v).strip().lower()


def score_question(org: str, q: dict, ans: dict) -> dict:
    kind, exp = q["kind"], q["expected"]
    if kind == "scalar":
        ok = norm(ans.get("value")) == norm(exp["value"])
        return {"primary": 1.0 if ok else 0.0, "correct": ok}
    if kind == "set":
        got, want = set(map(str, ans.get("values") or [])), set(map(str, exp["values"]))
        p = len(got & want) / len(got) if got else (1.0 if not want else 0.0)
        r = len(got & want) / len(want) if want else 1.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        extra = {}
        if "depth" in exp and q["params"].get("field") == "deepest":
            extra["depth_match"] = ans.get("depth") == exp["depth"]
        return {"primary": f1, "precision": p, "recall": r, "f1": f1, **extra}
    if kind == "ranked":
        got = [str(v) for v in (ans.get("values") or [])]
        rel = set(map(str, exp["relevant"]))
        k = exp["k"]
        topk = got[:k]
        p_at_k = len([v for v in topk if v in rel]) / k if k else 0.0
        rr = 0.0
        for i, v in enumerate(got):
            if v in rel:
                rr = 1.0 / (i + 1)
                break
        return {"primary": (p_at_k + rr) / 2, "p_at_k": p_at_k, "mrr": rr, "k": k}
    if kind == "path":
        start_ok = norm(ans.get("start")) == norm(exp["start"])
        end_ok = norm(ans.get("end_purl")) == norm(exp["end_purl"])
        depth_ok = ans.get("depth") == exp["depth"]
        val = validate_path(org, ans.get("path"), ans.get("rels"),
                            exp["start"], q["params"]["cve"])
        endpoint_acc = (start_ok + end_ok + depth_ok) / 3
        return {"primary": endpoint_acc, "start_ok": start_ok, "end_ok": end_ok,
                "depth_ok": depth_ok, "path_cited": val["cited"], "path_valid": val["valid"]}
    raise ValueError(f"unknown kind {kind}")


def run_system(system, questions: list[dict], org: str) -> dict:
    rows = []
    for q in questions:
        t0 = time.time()
        calls0, lat0 = system.calls, system.latency_ms
        try:
            ans = system.answer(q)
            error = None
        except Exception as e:
            ans, error = {}, f"{type(e).__name__}: {e}"
        wall_ms = (time.time() - t0) * 1000
        s = score_question(org, q, ans) if error is None else {
            "primary": 0.0, "error": True}
        rows.append({"id": q["id"], "group": q["group"], "kind": q["kind"],
                     "score": s, "error": error,
                     "calls": system.calls - calls0,
                     "tool_latency_ms": round(system.latency_ms - lat0, 1),
                     "wall_ms": round(wall_ms, 1)})
    return {"system": system.name, "rows": rows, "aggregate": aggregate(rows),
            "total_calls": system.calls,
            "total_tool_latency_ms": round(system.latency_ms, 1),
            "used_llm": getattr(system, "used_llm", False)}


def aggregate(rows: list[dict]) -> dict:
    agg: dict = {"n": len(rows),
                 "overall": round(sum(r["score"]["primary"] for r in rows) / len(rows), 3)}
    for grp in ("1-hop", "2-3-hop", "4-6-hop", "counterfactual"):
        sub = [r for r in rows if r["group"] == grp]
        if sub:
            agg[grp] = round(sum(r["score"]["primary"] for r in sub) / len(sub), 3)
    for kind in ("scalar", "set", "ranked", "path"):
        sub = [r for r in rows if r["kind"] == kind]
        if not sub:
            continue
        d: dict = {"n": len(sub),
                   "primary": round(sum(r["score"]["primary"] for r in sub) / len(sub), 3)}
        for m in ("correct", "precision", "recall", "f1", "p_at_k", "mrr",
                  "start_ok", "end_ok", "depth_ok", "path_cited", "path_valid"):
            vals = [r["score"][m] for r in sub if m in r["score"]
                    and isinstance(r["score"][m], (int, float, bool))]
            if vals:
                d[m] = round(sum(vals) / len(vals), 3)
        agg[kind] = d
    agg["avg_calls"] = round(sum(r["calls"] for r in rows) / len(rows), 1)
    agg["avg_wall_ms"] = round(sum(r["wall_ms"] for r in rows) / len(rows), 1)
    agg["errors"] = sum(1 for r in rows if r["error"])
    return agg


def disable_graph():
    from mcp_server import graph

    def _off(*a, **k):
        raise RuntimeError("graph unavailable (ablation: FalkorDB removed)")

    graph.run = _off
    graph.run_on = _off
    graph.connect = _off


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", default="all", choices=["all", "dev", "heldout"])
    ap.add_argument("--writer", default="proxy", choices=["proxy", "llm"])
    ap.add_argument("--ablate", action="store_true",
                    help="graph-removed ablation: agent only, graph layer disabled")
    ap.add_argument("--systems", default="all",
                    help="comma list: agent,flat,cypher (default all)")
    args = ap.parse_args()

    from benchmark.systems.agent_sys import AgentSystem
    from benchmark.systems.flat_sys import FlatSystem
    from benchmark.systems.cypher_sys import CypherSystem

    if args.ablate:
        disable_graph()

    orgs = ["dev", "heldout"] if args.org == "all" else [args.org]
    want = set(args.systems.split(",")) if args.systems != "all" else {"agent", "flat", "cypher"}
    RESULTS.mkdir(parents=True, exist_ok=True)

    for org in orgs:
        questions = json.loads((ROOT / "benchmark" / "questions" / f"{org}.json").read_text())
        out = {"org": org, "n_questions": len(questions),
               "writer": args.writer, "ablated": args.ablate, "systems": []}
        if "agent" in want:
            out["systems"].append(run_system(AgentSystem(org), questions, org))
        if not args.ablate and "flat" in want:
            out["systems"].append(run_system(FlatSystem(org), questions, org))
        if not args.ablate and "cypher" in want:
            out["systems"].append(run_system(CypherSystem(org, args.writer), questions, org))
        suffix = "_ablation" if args.ablate else ""
        path = RESULTS / f"{org}{suffix}.json"
        path.write_text(json.dumps(out, indent=2))
        print(f"{org}{suffix}: " + " | ".join(
            f"{s['system']} overall={s['aggregate']['overall']}" for s in out["systems"]))


if __name__ == "__main__":
    main()
