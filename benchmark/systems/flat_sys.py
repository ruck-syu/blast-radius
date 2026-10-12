"""System 1 (baseline): flat tables + lexical retrieval, no graph traversal.

Stands in for the vector-RAG/flat-table baseline: the same seed data is
exported to SQLite, entities are extracted by keyword match, and answers come
from single-join SQL only (no recursive CTEs, no transitive closure). This is
the documented restriction under test: flat retrieval cannot follow
multi-hop dependency or call chains.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CVES = ["CVE-2021-44228", "CVE-2024-3094", "CVE-2017-5638"]


def build_db(org: str) -> sqlite3.Connection:
    seed = json.loads((ROOT / "ingest" / f"seed_{org}.json").read_text())
    db = sqlite3.connect(":memory:")
    db.executescript("""
      CREATE TABLE cve(id TEXT, cvss REAL, summary TEXT);
      CREATE TABLE vuln(cve TEXT, purl TEXT);
      CREATE TABLE svc_use(service TEXT, purl TEXT);
      CREATE TABLE service(name TEXT, tier TEXT);
      CREATE TABLE endpoint(path TEXT, service TEXT, pub INT);
      CREATE TABLE calls(caller TEXT, callee TEXT);
      CREATE TABLE owns(service TEXT, team TEXT);
      CREATE TABLE deploys(service TEXT, person TEXT, ts INT);
    """)
    V = len(seed["vuln_pkgs"])
    all_pkgs = seed["vuln_pkgs"] + seed["fixed_pkgs"] + seed["packages"]
    db.executemany("INSERT INTO cve VALUES (?,?,?)",
                   [(c["id"], c["cvss"], c["summary"]) for c in seed["cves"]])
    db.executemany("INSERT INTO vuln VALUES (?,?)",
                   [(c["id"], c["vuln_pkg"]["purl"]) for c in seed["cves"]])
    db.executemany("INSERT INTO svc_use VALUES (?,?)",
                   [(seed["services"][s]["name"], all_pkgs[gi]["purl"]) for s, gi in seed["uses"]])
    db.executemany("INSERT INTO service VALUES (?,?)",
                   [(s["name"], s["tier"]) for s in seed["services"]])
    db.executemany("INSERT INTO endpoint VALUES (?,?,?)",
                   [(e["path"], seed["services"][e["to"]]["name"], int(e["public"])) for e in seed["endpoints"]])
    db.executemany("INSERT INTO calls VALUES (?,?)",
                   [(seed["services"][a]["name"], seed["services"][b]["name"]) for a, b in seed["calls"]])
    db.executemany("INSERT INTO owns VALUES (?,?)",
                   [(s["name"], seed["teams"][i % len(seed["teams"])]["name"])
                    for i, s in enumerate(seed["services"])])
    db.executemany("INSERT INTO deploys VALUES (?,?,?)",
                   [(seed["services"][d["service"]]["name"], seed["persons"][d["by"]]["name"], d["timestamp"])
                    for d in seed["deployments"]])
    return db


class FlatSystem:
    name = "flat-lexical-tables"

    def __init__(self, org: str):
        self.org = org
        self.db = build_db(org)
        self.calls = 0
        self.latency_ms = 0.0

    def _q(self, sql: str, args: tuple = ()):
        t0 = time.time()
        try:
            return self.db.execute(sql, args).fetchall()
        finally:
            self.calls += 1
            self.latency_ms += (time.time() - t0) * 1000

    def answer(self, q: dict) -> dict:
        p = q["params"]
        f = p.get("field")
        cve = p.get("cve")
        if f == "team":
            r = self._q("SELECT team FROM owns WHERE service=?", (p["service"],))
            return {"value": r[0][0] if r else None}
        if f == "deployer":
            r = self._q("SELECT person FROM deploys WHERE service=? ORDER BY ts DESC LIMIT 1",
                        (p["service"],))
            return {"value": r[0][0] if r else None}
        if f == "tier":
            r = self._q("SELECT tier FROM service WHERE name=?", (p["service"],))
            return {"value": r[0][0] if r else None}
        if f in ("affected_yn", "affected_count", "affected_maxdepth", "affected_set",
                 "deepest", "affected_union", "set_difference"):
            return self._affected(q)
        if f in ("reachable_yn", "reachable_set"):
            return self._reachable(q)
        if f == "team_affected":
            aff = self._affected_set(cve)
            team = {x[0] for x in self._q("SELECT service FROM owns WHERE team=?", (p["team"],))}
            return {"values": sorted(aff & team)}
        if f == "entry_services":
            # single join: services routed from a public endpoint (no CALLS* traversal)
            r = self._q("SELECT service FROM endpoint WHERE pub=1")
            return {"values": sorted({x[0] for x in r})}
        if f in ("depth", "proof_path"):
            # flat tables have no path concept
            return {"value": -1} if f == "depth" else \
                {"start": None, "end_purl": None, "depth": -1, "path": None}
        if f == "top_k":
            # no risk model: order by tier only
            order = {"critical": 0, "standard": 1, "internal": 2}
            aff = self._affected_set(cve)
            tiers = {n: t for n, t in self._q("SELECT name, tier FROM service")}
            ranked = sorted(aff, key=lambda s: (order.get(tiers.get(s, ""), 9), s))
            return {"values": ranked[: p["k"]]}
        if f == "cves_for_service":
            pkgs = [x[0] for x in self._q("SELECT purl FROM svc_use WHERE service=?", (p["service"],))]
            out = [c for c in CVES if self._q(
                "SELECT 1 FROM vuln WHERE cve=? AND purl IN (%s)" % ",".join("?" * len(pkgs)) if pkgs else "SELECT 0 WHERE 0",
                ((c, *pkgs) if pkgs else ()))]
            return {"values": sorted(out)}
        if f in ("reachable_after_fix", "best_fix", "reachable_removed", "fix_ranking",
                 "affected_after_other_fix"):
            return self._counterfactual(q)
        raise ValueError(f"flat: unsupported field {f}")

    # -- single-hop affected: services USEing the vulnerable package directly --
    def _affected_set(self, cve: str) -> set:
        v = self._q("SELECT purl FROM vuln WHERE cve=?", (cve,))
        if not v:
            return set()
        r = self._q("SELECT service FROM svc_use WHERE purl=?", (v[0][0],))
        return {x[0] for x in r}

    def _affected(self, q: dict) -> dict:
        p, f, cve = q["params"], q["params"].get("field"), q["params"].get("cve")
        if f == "affected_union":
            out = set()
            for c in CVES:
                out |= self._affected_set(c)
            return {"values": sorted(out)}
        if f == "set_difference":
            return {"values": sorted(self._affected_set(cve) - self._affected_set(p["other"]))}
        s = self._affected_set(cve)
        if f == "affected_yn":
            return {"value": "yes" if p["service"] in s else "no"}
        if f == "affected_count":
            return {"value": len(s)}
        if f in ("affected_maxdepth", "affected_set"):
            return {"values": sorted(s)}
        if f == "deepest":
            return {"values": sorted(s), "depth": 1} if s else {"values": [], "depth": 0}
        raise ValueError(f"flat affected: {f}")

    def _reachable_set(self, cve: str) -> set:
        # single join only: affected (single-hop) services that are public entry points
        aff = self._affected_set(cve)
        entries = {x[0] for x in self._q("SELECT service FROM endpoint WHERE pub=1")}
        return aff & entries

    def _reachable(self, q: dict) -> dict:
        p, f, cve = q["params"], q["params"].get("field"), q["params"].get("cve")
        if f == "reachable_yn":
            entries = {x[0] for x in self._q("SELECT service FROM endpoint WHERE pub=1")}
            one = {x[0] for x in self._q("SELECT callee FROM calls WHERE caller IN "
                                         "(SELECT service FROM endpoint WHERE pub=1)")}
            return {"value": "yes" if p["service"] in entries | one else "no"}
        return {"values": sorted(self._reachable_set(cve))}

    def _counterfactual(self, q: dict) -> dict:
        p, f = q["params"], q["params"].get("field")
        if f == "fix_ranking":
            # rank by single-hop reachable removed
            scored = [(c, len(self._reachable_set(c))) for c in CVES]
            ranked = sorted(scored, key=lambda t: (-t[1], t[0]))
            return {"values": [c for c, _ in ranked]}
        if f == "best_fix":
            ranked = self._counterfactual({"params": {"field": "fix_ranking"}})["values"]
            return {"value": ranked[0] if ranked else None}
        if f == "reachable_removed":
            return {"value": len(self._reachable_set(p["cve"]))}
        if f == "reachable_after_fix":
            rest = set()
            for c in CVES:
                if c != p["cve"]:
                    rest |= self._reachable_set(c)
            return {"value": len(rest)}
        if f == "affected_after_other_fix":
            return {"value": len(self._affected_set(p["cve"]))}
        raise ValueError(f"flat counterfactual: {f}")
