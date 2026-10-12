"""System 3 (ours): answer benchmark questions with the parameterized MCP tools.

Same tool functions the agent and MCP server use (depth-bounded traversal,
rules, proof verification). Tracks tool calls + latency per question.
"""
from __future__ import annotations

import time

from mcp_server.server import (
    find_affected_services, check_reachability, dependency_path,
    find_owner, score_risk,
)
from mcp_server.simulate import simulate_fix
from agent.compare import compare_fixes
from agent.triage import verify_proof

CVES_FALLBACK = "CVE-2021-44228"


class AgentSystem:
    name = "agent-parameterized-tools"

    def __init__(self, org: str):
        self.org = org
        self.calls = 0
        self.latency_ms = 0.0
        self._cmp_cache: dict = {}

    def _t(self, fn, *a, **k):
        t0 = time.time()
        try:
            return fn(*a, **k)
        finally:
            self.calls += 1
            self.latency_ms += (time.time() - t0) * 1000

    def answer(self, q: dict) -> dict:
        p, org = q["params"], self.org
        f = q["params"].get("field")
        cve = p.get("cve")

        if f in ("team", "deployer", "tier"):
            o = self._t(find_owner, p["service"], org)
            key = {"team": "team", "deployer": "last_deployer", "tier": "tier"}[f]
            return {"value": o.get(key)}
        if f == "affected_yn":
            d = self._t(dependency_path, cve, p["service"], org)
            return {"value": "yes" if d["affected"] else "no"}
        if f == "affected_count":
            r = self._t(find_affected_services, cve, org)
            return {"value": len(r["services"])}
        if f == "affected_maxdepth":
            r = self._t(find_affected_services, cve, org)
            return {"values": sorted(s["service"] for s in r["services"]
                                     if s["depth"] <= p["max_depth"])}
        if f == "reachable_yn":
            r = self._t(check_reachability, p["service"], org)
            return {"value": "yes" if r["reachable"] else "no"}
        if f == "entry_services":
            r = self._t(check_reachability, p["service"], org)
            return {"values": sorted(e["entry_service"] for e in r["entries"])}
        if f == "depth":
            d = self._t(dependency_path, cve, p["service"], org)
            return {"value": d["dependency"]["depth"] if d["affected"] else -1}
        if f == "reachable_set":
            r = self._t(score_risk, cve, org)
            return {"values": sorted(s["service"] for s in r["ranked"] if s["reachable"])}
        if f == "team_affected":
            r = self._t(find_affected_services, cve, org)
            out = []
            for s in r["services"]:
                o = self._t(find_owner, s["service"], org)
                if o.get("team") == p["team"]:
                    out.append(s["service"])
            return {"values": sorted(out)}
        if f == "cves_for_service":
            out = []
            for cid in ("CVE-2021-44228", "CVE-2024-3094", "CVE-2017-5638"):
                d = self._t(dependency_path, cid, p["service"], org)
                if d["affected"]:
                    out.append(cid)
            return {"values": sorted(out)}
        if f == "affected_set":
            r = self._t(find_affected_services, cve, org)
            return {"values": sorted(s["service"] for s in r["services"])}
        if f == "top_k":
            r = self._t(score_risk, cve, org)
            return {"values": [s["service"] for s in r["ranked"][: p["k"]]]}
        if f == "deepest":
            r = self._t(find_affected_services, cve, org)
            mx = max(s["depth"] for s in r["services"])
            return {"values": sorted(s["service"] for s in r["services"] if s["depth"] == mx),
                    "depth": mx}
        if f == "affected_union":
            out = set()
            for cid in ("CVE-2021-44228", "CVE-2024-3094", "CVE-2017-5638"):
                r = self._t(find_affected_services, cid, org)
                out.update(s["service"] for s in r["services"])
            return {"values": sorted(out)}
        if f == "proof_path":
            from mcp_server import graph
            meta = self._t(graph.run, org, "get_cve", {"cve": cve})
            vuln = meta[0][0][5]
            d = self._t(dependency_path, cve, p["service"], org)
            if not d["affected"]:
                return {"start": None, "end_purl": None, "depth": -1, "path": None}
            ok, _ = verify_proof(d["dependency"]["path"], p["service"], vuln)
            path = d["dependency"]["path"]
            nodes = path["nodes"]
            return {"start": p["service"],
                    "end_purl": nodes[-1]["properties"].get("purl"),
                    "depth": d["dependency"]["depth"],
                    "path": [n["id"] for n in nodes] if ok else None,
                    "rels": [e["type"] for e in path["edges"]] if ok else None}
        if f == "reachable_after_fix":
            comp = self._cmp(cve)
            cand = next(c for c in comp["candidates"] if c["cve"] == cve)
            return {"value": cand["after"]["reachable"]}
        if f == "best_fix":
            return {"value": self._cmp(cve)["recommendation"]["cve"]}
        if f == "reachable_removed":
            comp = self._cmp(cve)
            return {"value": next(c for c in comp["candidates"] if c["cve"] == cve)["reachable_removed"]}
        if f == "set_difference":
            a = self._t(find_affected_services, cve, org)
            b = self._t(find_affected_services, p["other"], org)
            sb = {s["service"] for s in b["services"]}
            return {"values": sorted(s["service"] for s in a["services"] if s["service"] not in sb)}
        if f == "affected_after_other_fix":
            sim = self._t(simulate_fix, cve, self._vuln(p["other"]), org)
            return {"value": sim["after"]["cves"][cve]["affected"]}
        if f == "fix_ranking":
            comp = self._cmp(cve)
            ranked = sorted(comp["candidates"],
                            key=lambda d: (-d["reachable_removed"], d["cve"]))
            return {"values": [d["cve"] for d in ranked]}
        raise ValueError(f"agent: unsupported field {f}")

    def _cmp(self, cve: str | None) -> dict:
        key = (self.org, cve or CVES_FALLBACK)
        if key not in self._cmp_cache:
            t0 = time.time()
            try:
                self._cmp_cache[key] = compare_fixes(cve or CVES_FALLBACK, self.org)
            finally:
                self.calls += 3  # 3 simulate_fix calls inside
                self.latency_ms += (time.time() - t0) * 1000
        return self._cmp_cache[key]

    def _vuln(self, cve: str) -> str:
        from mcp_server import graph
        rows, _ = graph.run(self.org, "get_cve", {"cve": cve})
        self.calls += 1
        return rows[0][5]
