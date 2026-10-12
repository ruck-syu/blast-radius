"""Load seed_<org>.json into FalkorDB.

Usage:
  python -m ingest.load --org dev
  python -m ingest.load --all

Rebuilds the org's graph from scratch (deletes existing graph first).
Prints node/edge counts for the Phase 1 record.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from falkordb import FalkorDB

from .config import HOST, PORT, USERNAME, PASSWORD, graph_name

HERE = Path(__file__).resolve().parent
BATCH = 2000


def connect():
    kwargs = {"host": HOST, "port": PORT}
    if USERNAME:
        kwargs["username"] = USERNAME
    if PASSWORD:
        kwargs["password"] = PASSWORD
    return FalkorDB(**kwargs)


def q(g, cypher: str, params: dict | None = None):
    return g.query(cypher, params or {})


def batched(g, cypher: str, rows: list[dict], label: str):
    t0 = time.time()
    for i in range(0, len(rows), BATCH):
        chunk = rows[i:i + BATCH]
        g.query(cypher, {"rows": chunk})
    dt = time.time() - t0
    print(f"  {label}: {len(rows)} rows in {dt:.1f}s")


def load_org(org: str) -> dict:
    seed = json.loads((HERE / f"seed_{org}.json").read_text())
    db = connect()
    name = graph_name(org)
    try:
        db.select_graph(name).delete()
        print(f"deleted existing graph {name}")
    except Exception:
        pass
    g = db.select_graph(name)

    # Indexes on lookup keys (spec section 4). Tolerate syntax differences.
    for stmt in [
        "CREATE INDEX FOR (c:CVE) ON (c.id)",
        "CREATE INDEX FOR (p:Package) ON (p.purl)",
        "CREATE INDEX FOR (s:Service) ON (s.name)",
    ]:
        try:
            g.query(stmt)
        except Exception as e:
            print(f"  index note: {e}")

    V = len(seed["vuln_pkgs"])
    all_pkgs = seed["vuln_pkgs"] + seed["fixed_pkgs"] + seed["packages"]

    def purl_of(gidx: int) -> str:
        return all_pkgs[gidx]["purl"]

    t0 = time.time()
    batched(g, "UNWIND $rows AS r CREATE (:CVE {id: r.id, cvss: r.cvss, epss: r.epss, "
                 "in_kev: r.in_kev, summary: r.summary, published: r.published})",
            [{k: c[k] for k in ("id", "cvss", "epss", "in_kev", "summary", "published")}
             for c in seed["cves"]], "CVE nodes")
    batched(g, "UNWIND $rows AS r CREATE (:Package {name: r.name, version: r.version, "
                 "ecosystem: r.ecosystem, purl: r.purl, synthetic: r.synthetic})",
            [{**p, "synthetic": p.get("synthetic", False)} for p in all_pkgs], "Package nodes")
    batched(g, "UNWIND $rows AS r CREATE (:Service {name: r.name, tier: r.tier, "
                 "repo: r.repo, language: r.language, synthetic: r.synthetic})",
            seed["services"], "Service nodes")
    batched(g, "UNWIND $rows AS r CREATE (:Endpoint {path: r.path, public: r.public, synthetic: r.synthetic})",
            [{k: e[k] for k in ("path", "public", "synthetic")} for e in seed["endpoints"]], "Endpoint nodes")
    batched(g, "UNWIND $rows AS r CREATE (:Team {name: r.name, slack_channel: r.slack_channel, synthetic: r.synthetic})",
            seed["teams"], "Team nodes")
    batched(g, "UNWIND $rows AS r CREATE (:Person {name: r.name, handle: r.handle, synthetic: r.synthetic})",
            [{k: p[k] for k in ("name", "handle", "synthetic")} for p in seed["persons"]], "Person nodes")
    batched(g, "UNWIND $rows AS r CREATE (:Deployment {id: r.id, timestamp: r.timestamp, "
                 "version: r.version, synthetic: r.synthetic})",
            [{k: d[k] for k in ("id", "timestamp", "version", "synthetic")} for d in seed["deployments"]],
            "Deployment nodes")
    batched(g, "UNWIND $rows AS r CREATE (:Rule {id: r.id, description: r.description, weight: r.weight})",
            seed["rules"], "Rule nodes")

    # Edges (match on indexed keys, batched).
    batched(g, "UNWIND $rows AS r MATCH (c:CVE {id: r.cve}), (p:Package {purl: r.purl}) "
                 "CREATE (c)-[:AFFECTS {range: r.range}]->(p)",
            [{"cve": c["id"], "purl": c["vuln_pkg"]["purl"], "range": c["range"]} for c in seed["cves"]],
            "AFFECTS")
    batched(g, "UNWIND $rows AS r MATCH (c:CVE {id: r.cve}), (p:Package {purl: r.purl}) "
                 "CREATE (c)-[:FIXED_IN]->(p)",
            [{"cve": c["id"], "purl": c["fixed_pkg"]["purl"]} for c in seed["cves"]], "FIXED_IN")
    batched(g, "UNWIND $rows AS r MATCH (a:Package {purl: r.from}), (b:Package {purl: r.to}) "
                 "CREATE (a)-[:SUPERSEDED_BY]->(b)",
            [{"from": c["vuln_pkg"]["purl"], "to": c["fixed_pkg"]["purl"]} for c in seed["cves"]],
            "SUPERSEDED_BY")
    batched(g, "UNWIND $rows AS r MATCH (a:Package {purl: r.child}), (b:Package {purl: r.parent}) "
                 "CREATE (a)-[:DEPENDS_ON]->(b)",
            [{"child": purl_of(c), "parent": purl_of(p)} for c, p in seed["depends_on"]], "DEPENDS_ON")
    batched(g, "UNWIND $rows AS r MATCH (s:Service {name: r.svc}), (p:Package {purl: r.purl}) "
                 "CREATE (s)-[:USES]->(p)",
            [{"svc": seed["services"][s]["name"], "purl": purl_of(gi)} for s, gi in seed["uses"]], "USES")
    batched(g, "UNWIND $rows AS r MATCH (a:Service {name: r.caller}), (b:Service {name: r.callee}) "
                 "CREATE (a)-[:CALLS]->(b)",
            [{"caller": seed["services"][a]["name"], "callee": seed["services"][b]["name"]}
             for a, b in seed["calls"]], "CALLS")
    batched(g, "UNWIND $rows AS r MATCH (e:Endpoint {path: r.path}), (s:Service {name: r.svc}) "
                 "CREATE (e)-[:ROUTES_TO]->(s)",
            [{"path": e["path"], "svc": seed["services"][e["to"]]["name"]} for e in seed["endpoints"]],
            "ROUTES_TO")
    batched(g, "UNWIND $rows AS r MATCH (s:Service {name: r.svc}), (t:Team {name: r.team}) "
                 "CREATE (s)-[:OWNED_BY]->(t)",
            [{"svc": s["name"], "team": seed["teams"][i % len(seed["teams"])]["name"]}
             for i, s in enumerate(seed["services"])], "OWNED_BY")
    batched(g, "UNWIND $rows AS r MATCH (p:Person {handle: r.handle}), (t:Team {name: r.team}) "
                 "CREATE (p)-[:MEMBER_OF]->(t)",
            [{"handle": p["handle"], "team": seed["teams"][p["team"]]["name"]} for p in seed["persons"]],
            "MEMBER_OF")
    batched(g, "UNWIND $rows AS r MATCH (p:Person {handle: r.handle}), (d:Deployment {id: r.dep}) "
                 "CREATE (p)-[:DEPLOYED]->(d)",
            [{"handle": seed["persons"][d["by"]]["handle"], "dep": d["id"]} for d in seed["deployments"]],
            "DEPLOYED")
    batched(g, "UNWIND $rows AS r MATCH (d:Deployment {id: r.dep}), (s:Service {name: r.svc}) "
                 "CREATE (d)-[:OF]->(s)",
            [{"dep": d["id"], "svc": seed["services"][d["service"]]["name"]} for d in seed["deployments"]],
            "OF")

    nodes = g.query("MATCH (n) RETURN count(n) AS c").result_set[0][0]
    edges = g.query("MATCH ()-[r]->() RETURN count(r) AS c").result_set[0][0]
    dt = time.time() - t0
    print(f"{org} -> graph {name}: {nodes} nodes, {edges} edges in {dt:.0f}s")
    return {"graph": name, "nodes": nodes, "edges": edges}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", choices=["dev", "heldout"])
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()
    orgs = ["dev", "heldout"] if args.all else [args.org or "dev"]
    counts = {}
    for org in orgs:
        counts[org] = load_org(org)
    out = HERE.parent / "benchmark" / "counts.json"
    prev = json.loads(out.read_text()) if out.exists() else {}
    prev.update(counts)
    out.write_text(json.dumps(prev, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
