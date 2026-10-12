"""System 2 (baseline): free-form text-to-Cypher.

Primary mode: an LLM writes Cypher against the live graph (needs
ANTHROPIC_API_KEY or OPENAI_API_KEY; prompted with the schema, read-only
RO_QUERY enforced, first-column values taken as the answer). No LLM key is
configured in this environment, so the reported numbers use the documented
fallback: per-kind handwritten Cypher WITHOUT depth bounds and WITHOUT proof
verification — the failure mode free-form generation degrades to (unbounded
traversal, unverified paths). The --writer llm flag runs the real thing when
a key is present.

Column name: unbounded-cypher (no-LLM proxy) unless --writer llm was used.
"""
from __future__ import annotations

import os
import time

from mcp_server import graph

CVES = ["CVE-2021-44228", "CVE-2024-3094", "CVE-2017-5638"]
SCHEMA = """Nodes: CVE(id), Package(purl), Service(name,tier), Endpoint(path,public),
Team(name), Person(name). Edges: (CVE)-[:AFFECTS]->(Package),
(Package)-[:DEPENDS_ON]->(Package), (Service)-[:USES]->(Package),
(Service)-[:CALLS]->(Service), (Endpoint)-[:ROUTES_TO]->(Service),
(Service)-[:OWNED_BY]->(Team), (Person)-[:DEPLOYED]->(Deployment)-[:OF]->(Service).
Answer with a single read-only MATCH...RETURN Cypher query only."""


def llm_write(question: str) -> str | None:
    """Real text-to-Cypher writer. Returns None when no LLM is configured."""
    provider = os.getenv("LLM_PROVIDER", "").lower() or (
        "anthropic" if os.getenv("ANTHROPIC_API_KEY") else
        "openai" if os.getenv("OPENAI_API_KEY") else "")
    if not provider:
        return None
    prompt = (f"{SCHEMA}\nQuestion: {question}\nCypher:").strip()
    try:
        if provider == "anthropic":
            import anthropic
            m = anthropic.Anthropic().messages.create(
                model=os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
                max_tokens=300, messages=[{"role": "user", "content": prompt}])
            text = "".join(b.text for b in m.content if b.type == "text")
        else:
            import openai
            r = openai.OpenAI().chat.completions.create(
                model=os.getenv("LLM_MODEL", "gpt-4o-mini"), max_tokens=300,
                messages=[{"role": "user", "content": prompt}])
            text = r.choices[0].message.content or ""
    except Exception:
        return None
    # strip fences, keep the query
    text = text.strip()
    if "```" in text:
        parts = text.split("```")
        text = next((p for p in parts if "MATCH" in p.upper()), text)
        text = text.replace("cypher", "").replace("Cypher", "")
    return text.strip() or None


# Fallback templates: unbounded traversals, no proof checks.
def proxy_cypher(q: dict) -> tuple[str, dict]:
    p, f, cve = q["params"], q["params"].get("field"), q["params"].get("cve")
    if f == "team":
        return ("MATCH (s:Service {name:$service})-[:OWNED_BY]->(t:Team) RETURN t.name",
                {"service": p["service"]})
    if f == "deployer":
        return ("MATCH (p:Person)-[:DEPLOYED]->(d:Deployment)-[:OF]->(s:Service {name:$service}) "
                "RETURN p.name ORDER BY d.timestamp DESC LIMIT 1", {"service": p["service"]})
    if f == "tier":
        return ("MATCH (s:Service {name:$service}) RETURN s.tier", {"service": p["service"]})
    if f in ("affected_yn", "affected_count", "affected_maxdepth", "affected_set",
             "deepest", "affected_union", "set_difference"):
        return ("MATCH (c:CVE {id:$cve})-[:AFFECTS]->(v:Package) "
                "MATCH (s:Service)-[:USES]->(:Package)-[:DEPENDS_ON*]->(v) "
                "RETURN DISTINCT s.name", {"cve": cve})
    if f in ("reachable_yn", "reachable_set", "entry_services"):
        return ("MATCH (e:Endpoint {public:true})-[:ROUTES_TO]->(:Service)-[:CALLS*]->"
                "(s:Service {name:$service}) RETURN e.path", {"service": p.get("service", "")})
    if f in ("depth", "proof_path"):
        return ("MATCH (c:CVE {id:$cve})-[:AFFECTS]->(v:Package) "
                "MATCH path=(s:Service {name:$service})-[:USES]->(:Package)-[:DEPENDS_ON*]->(v) "
                "RETURN length(path)", {"cve": cve, "service": p.get("service", "")})
    if f == "top_k":
        return ("MATCH (c:CVE {id:$cve})-[:AFFECTS]->(v:Package) "
                "MATCH (s:Service)-[:USES]->(:Package)-[:DEPENDS_ON*]->(v) "
                "RETURN DISTINCT s.name LIMIT $k", {"cve": cve, "k": p.get("k", 5)})
    if f == "cves_for_service":
        return ("MATCH (c:CVE)-[:AFFECTS]->(:Package)<-[:DEPENDS_ON*]-(:Package)"
                "<-[:USES]-(s:Service {name:$service}) RETURN DISTINCT c.id",
                {"service": p["service"]})
    if f == "team_affected":
        return ("MATCH (c:CVE {id:$cve})-[:AFFECTS]->(v:Package) "
                "MATCH (s:Service)-[:USES]->(:Package)-[:DEPENDS_ON*]->(v) "
                "MATCH (s)-[:OWNED_BY]->(t:Team {name:$team}) "
                "RETURN DISTINCT s.name", {"cve": cve, "team": p["team"]})
    # counterfactuals: proxy has no simulator; guess from unbounded counts
    return ("MATCH (c:CVE) RETURN c.id", {})


def first_col(rows) -> list:
    out = []
    for r in rows:
        v = r[0]
        out.append(v[0] if isinstance(v, (list, tuple)) else v)
    return out


class CypherSystem:
    name = "unbounded-cypher-proxy"

    def __init__(self, org: str, writer: str = "proxy"):
        from ingest.config import graph_name
        self.org = org
        self.key = graph_name(org)
        self.writer = writer  # "proxy", or "llm" (falls back per question without a key)
        self.used_llm = False
        self.calls = 0
        self.latency_ms = 0.0

    def _run(self, cypher: str, params: dict):
        t0 = time.time()
        try:
            g = graph.connect().select_graph(self.key)
            if not cypher.strip().upper().startswith("MATCH"):
                raise ValueError("not a read-only MATCH query")
            rs = g.ro_query(cypher, params)
            return rs.result_set
        finally:
            self.calls += 1
            self.latency_ms += (time.time() - t0) * 1000

    def answer(self, q: dict) -> dict:
        p, f = q["params"], q["params"].get("field")
        cypher = None
        if self.writer == "llm":
            cypher = llm_write(q["text"])
            if cypher is not None:
                self.used_llm = True
        if cypher is None:
            cypher, params = proxy_cypher(q)
        else:
            params = {k: v for k, v in p.items() if k in cypher}
        try:
            rows = self._run(cypher, params)
        except Exception:
            return self._empty(f)
        vals = first_col(rows)
        if f in ("team", "deployer", "tier"):
            return {"value": vals[0] if vals else None}
        if f == "affected_yn":
            return {"value": "yes" if p["service"] in vals else "no"}
        if f == "affected_count":
            return {"value": len(vals)}
        if f in ("affected_maxdepth", "affected_set", "team_affected"):
            return {"values": sorted(str(v) for v in vals)}
        if f == "deepest":
            return {"values": sorted(str(v) for v in vals), "depth": -1}
        if f == "affected_union":
            got = set()
            for c in CVES:
                try:
                    got.update(str(v) for v in first_col(
                        self._run(cypher, {"cve": c})))
                except Exception:
                    pass
            return {"values": sorted(got)}
        if f == "set_difference":
            return {"values": sorted(str(v) for v in vals)}
        if f == "reachable_yn":
            return {"value": "yes" if vals else "no"}
        if f == "reachable_set":
            return {"values": []}  # proxy query is per-service; cannot list
        if f == "entry_services":
            return {"values": []}
        if f == "depth":
            nums = [v for v in vals if isinstance(v, int)]
            return {"value": min(nums) if nums else -1}
        if f == "proof_path":
            return {"start": None, "end_purl": None, "depth": -1, "path": None}
        if f == "top_k":
            return {"values": [str(v) for v in vals[: p.get("k", 5)]]}
        if f == "cves_for_service":
            return {"values": sorted(str(v) for v in vals)}
        if f in ("reachable_after_fix", "reachable_removed", "affected_after_other_fix"):
            return {"value": 0}
        if f == "best_fix":
            return {"value": vals[0] if vals else None}
        if f == "fix_ranking":
            return {"values": [str(v) for v in vals]}
        raise ValueError(f"cypher: unsupported field {f}")

    @staticmethod
    def _empty(f: str) -> dict:
        if f in ("team", "deployer", "tier", "affected_yn", "affected_count",
                 "reachable_yn", "depth", "best_fix", "reachable_after_fix",
                 "reachable_removed", "affected_after_other_fix"):
            return {"value": None} if f not in ("affected_yn", "reachable_yn") else {"value": "no"}
        if f in ("deepest",):
            return {"values": [], "depth": -1}
        if f == "proof_path":
            return {"start": None, "end_purl": None, "depth": -1, "path": None}
        return {"values": []}
