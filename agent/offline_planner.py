"""Offline planner: a fixed, rule-following policy that drives the MCP agent loop
without a model. NOT Claude: it never chooses tools from what it reads, it runs
the same sequence every time. It exists so the MCP client, the streamed trace,
the code re-checks and the approval flow can be exercised without an API key,
and as a baseline to compare a model's tool choices against.

Policy for "triage <CVE>": get_cve + score_risk, evaluate_rules for every ranked
service, find_owner for the ones the rules make ACT_NOW, rank_criticality once,
then submit_findings with the verdict the rules give.

  python -m agent.mcp_agent CVE-2021-44228 --offline
"""
from __future__ import annotations

import json

from .triage import verdict_for

LABEL = "Offline planner (no model): fixed tool sequence over the same MCP server."


def _use(name: str, reason: str, **args) -> dict:
    return {"type": "tool_use", "id": f"op_{name}_{args.get('service', '')}",
            "name": name, "input": {**args, "reason": reason}}


def _results(messages: list) -> dict[str, dict | None]:
    out = {}
    for b in messages[-1]["content"]:
        try:
            out[b["tool_use_id"]] = json.loads(b["content"])
        except (json.JSONDecodeError, TypeError):
            out[b["tool_use_id"]] = None
    return out


def offline_llm(cve: str | None, org: str = "dev"):
    """An llm(system, messages, tools) callable for agent.mcp_agent.run_agent."""
    state: dict = {}

    def llm(system, messages, tools):
        turn = sum(1 for m in messages if m["role"] == "assistant")
        if not cve:
            return [{"type": "text", "text": LABEL + " It only runs CVE triage; "
                     "free-form questions need Claude (set ANTHROPIC_API_KEY)."}], "end_turn"
        if turn == 0:
            return [{"type": "text", "text": LABEL},
                    _use("get_cve", "KEV status, CVSS and the vulnerable purl", cve=cve, org=org),
                    _use("score_risk", "affected services ranked by risk, with dependency paths",
                         cve=cve, org=org)], "tool_use"
        res = _results(messages)
        if turn == 1:
            ranked = (res.get("op_score_risk_") or {}).get("ranked", [])
            state["ranked"] = {r["service"]: r for r in ranked}
            if not ranked:
                return [_use("submit_findings", "no affected services",
                             summary=f"{cve}: no affected services in the {org} graph.",
                             findings=[])], "tool_use"
            return [_use("evaluate_rules", f"rules for {r['service']} (risk {r['risk']:.1f})",
                         cve=cve, service=r["service"], org=org) for r in ranked], "tool_use"
        if turn == 2:
            state["fired"] = {k.removeprefix("op_evaluate_rules_"): (v or {}).get("fired", [])
                              for k, v in res.items()}
            state["act"] = [s for s, f in state["fired"].items() if verdict_for(f)[0] == "ACT_NOW"]
            return [_use("find_owner", "ACT_NOW: who to notify", service=s, org=org)
                    for s in state["act"]] + [
                _use("rank_criticality", "call-graph centrality to order the work", org=org)], "tool_use"
        owners = {k.removeprefix("op_find_owner_"): v for k, v in res.items()
                  if k.startswith("op_find_owner_") and v}
        findings = []
        for s, fired in state["fired"].items():
            r, o = state["ranked"].get(s, {}), owners.get(s) or {}
            reach = f"public via {r['entry_point']}" if r.get("reachable") else "no public path"
            owner = f"; owner {o.get('team')} {o.get('slack_channel')}" if o.get("found") else ""
            findings.append({"service": s, "verdict": verdict_for(fired)[0],
                             "reason": f"{reach}; rules {', '.join(fired) or 'none'}{owner}"})
        n_act = len(state["act"])
        return [_use("submit_findings", "verdicts from the rules",
                     summary=(f"{cve}: {len(findings)} affected services, {n_act} ACT_NOW "
                              f"(verdicts taken from the rules; no model involved)."),
                     findings=findings)], "tool_use"

    return llm
