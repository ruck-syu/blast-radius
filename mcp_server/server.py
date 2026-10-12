"""Blast Radius MCP server: graph tools for the triage agent.

Tools: find_affected_services, check_reachability, dependency_path,
       rank_criticality, find_owner, score_risk, evaluate_rules, simulate_fix,
       apply_change, create_ticket, notify_owner, open_fix_pr (actions require proof_path).
Every tool runs parameterized Cypher from queries/*.cypher against FalkorDB,
returns structured output including graph path(s), and reports query latency.

Run:  python -m mcp_server.server   (stdio transport)
"""
from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from . import graph
from ingest.config import MAX_DEP_DEPTH, MAX_CALL_DEPTH

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("blast-radius.mcp")

mcp = FastMCP("blast-radius")


def _limit(value: int, default: int, maximum: int = 100) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ValueError(f"limit must be an int 1..{maximum}, got {value!r}")
    return value


@mcp.tool()
def find_affected_services(cve: str, org: str = "dev") -> dict:
    """Transitive traversal from a CVE to affected services. Returns services, depths, and proof paths."""
    rows, latency_ms = graph.run(org, "find_affected_services", {"cve": cve})
    services = [{"service": r[0], "depth": r[1], "path": graph.serialize_path(r[2])} for r in rows]
    return {"cve": cve, "org": org, "count": len(services),
            "services": services, "latency_ms": latency_ms}


@mcp.tool()
def check_reachability(service: str, org: str = "dev") -> dict:
    """Whether a service is reachable from a public endpoint. Returns entry paths."""
    rows, latency_ms = graph.run(org, "check_reachability", {"service": service})
    entries = [{"entry_point": r[0], "entry_service": r[1],
                "path": graph.serialize_path(r[2])} for r in rows]
    return {"service": service, "org": org, "reachable": bool(entries),
            "entries": entries, "latency_ms": latency_ms}


@mcp.tool()
def dependency_path(cve: str, service: str, org: str = "dev") -> dict:
    """Shortest explanation path from a CVE to a service (empty when unrelated)."""
    rows, latency_ms = graph.run(org, "dependency_path", {"cve": cve, "service": service})
    item = {"depth": rows[0][1], "path": graph.serialize_path(rows[0][0])} if rows else None
    return {"cve": cve, "service": service, "org": org,
            "affected": item is not None, "dependency": item, "latency_ms": latency_ms}


@mcp.tool()
def rank_criticality(org: str = "dev", limit: int = 20) -> dict:
    """Centrality ranking over the service CALLS graph, with call edges as evidence."""
    rows, lat1 = graph.run(org, "rank_criticality", {})
    edge_rows, lat2 = graph.run(org, "call_graph_edges", {})
    ranking = [{"service": r[0], "out_degree": r[1], "in_degree": r[2]} for r in rows]
    # NOTE: ranking order is produced by the Cypher ORDER BY; limit slices only.
    ranking = ranking[:_limit(limit, 20)]
    return {"org": org, "ranking": ranking,
            "call_graph_edges": [{"caller": r[0], "callee": r[1]} for r in edge_rows],
            "latency_ms": round(lat1 + lat2, 1)}


@mcp.tool()
def find_owner(service: str, org: str = "dev") -> dict:
    """Owning team, Slack channel, and most recent deployer of a service, with paths."""
    rows, latency_ms = graph.run(org, "find_owner", {"service": service})
    if not rows:
        return {"service": service, "org": org, "found": False, "latency_ms": latency_ms}
    r = rows[0]
    return {"service": service, "org": org, "found": True, "team": r[0],
            "slack_channel": r[1], "last_deployer": r[2], "deployed_at": r[3],
            "ownership_path": graph.serialize_path(r[4]),
            "deploy_path": graph.serialize_path(r[5]),
            "tier": r[6],
            "latency_ms": latency_ms}


@mcp.tool()
def score_risk(cve: str, org: str = "dev") -> dict:
    """Ranked affected services with risk = severity x exposure x criticality (computed in Cypher)."""
    rows, latency_ms = graph.run(org, "score_risk", {"cve": cve})
    ranked = [{"service": r[0], "tier": r[1], "depth": r[2], "severity": r[3],
               "exposure": r[4], "criticality": r[5], "risk": round(r[6], 2),
               "reachable": bool(r[7]), "entry_point": r[8],
               "path": graph.serialize_path(r[9])} for r in rows]
    return {"cve": cve, "org": org, "count": len(ranked),
            "ranked": ranked, "latency_ms": latency_ms}


@mcp.tool()
def evaluate_rules(cve: str, service: str, org: str = "dev") -> dict:
    """Which named rules fire for a CVE+service pair, with weights (computed in Cypher)."""
    rows, latency_ms = graph.run(org, "evaluate_rules", {"cve": cve, "service": service})
    rules = [{"rule": r[0], "weight": r[1], "fired": bool(r[2])} for r in rows]
    return {"cve": cve, "service": service, "org": org,
            "fired": [x["rule"] for x in rules if x["fired"]],
            "rules": rules, "latency_ms": latency_ms}


@mcp.tool()
def simulate_fix(cve: str, fix: str, org: str = "dev") -> dict:
    """Simulate upgrading package `fix` (purl) in a sandbox graph copy.

    Follows the real SUPERSEDED_BY/FIXED_IN upgrade path, re-scores, returns
    before/after risk and affected/reachable counts, deletes the sandbox.
    """
    from .simulate import simulate_fix as _simulate_fix
    return _simulate_fix(cve, fix, org)


@mcp.tool()
def create_ticket(cve: str, service: str, verdict: str, rationale: str,
                  proof_path: dict | None, rules: list[str] | None = None,
                  org: str = "dev") -> dict:
    """Open a ticket on our demo repo. Requires proof_path (verified, else refused)."""
    from .actions import create_ticket as _create_ticket
    return _create_ticket(cve, service, verdict, rationale, proof_path, rules, org)


@mcp.tool()
def notify_owner(cve: str, service: str, verdict: str, rationale: str,
                 proof_path: dict | None, channel: str = "",
                 rules: list[str] | None = None, org: str = "dev") -> dict:
    """Notify the owning team. Requires proof_path (verified, else refused)."""
    from .actions import notify_owner as _notify_owner
    return _notify_owner(cve, service, verdict, rationale, proof_path, channel, rules, org)


@mcp.tool()
def open_fix_pr(cve: str, service: str, verdict: str, rationale: str,
                proof_path: dict | None, fix: str = "",
                rules: list[str] | None = None, org: str = "dev") -> dict:
    """Propose a fix PR on our demo repo. Requires proof_path (verified, else refused)."""
    from .actions import open_fix_pr as _open_fix_pr
    return _open_fix_pr(cve, service, verdict, rationale, proof_path, fix, rules, org)


@mcp.tool()
def apply_change(kind: str, org: str = "dev", service: str = "", purl: str = "",
                 path: str = "", public: bool = False, ref_id: str = "",
                 version: str = "", by: str = "", timestamp: int = 0,
                 cvss: float = 0.0, epss: float = 0.0, summary: str = "",
                 published: str = "", affects_purl: str = "", vuln_range: str = "",
                 fixed_purl: str = "") -> dict:
    """Incrementally upsert a change (add_dependency|add_endpoint|add_deployment|add_cve)
    so the agent can re-triage with no retraining. Referenced nodes must exist."""
    from .apply import apply_change as _apply_change
    return _apply_change(kind, org, service, purl, path, public, ref_id,
                         version, by, timestamp, cvss, epss, summary,
                         published, affects_purl, vuln_range, fixed_purl)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
