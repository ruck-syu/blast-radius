"""MCP agent acceptance (offline): real MCP stdio server + FalkorDB, scripted LLM.

The scripted model stands in for Claude so the test needs no API key; everything
else is real: tool discovery via list_tools, tool calls over stdio, trace with
reasons, verdict re-derivation, proof verification, and the action guardrail.

  python -m agent.test_mcp_agent
"""
from __future__ import annotations

import asyncio
import copy
import json

from .mcp_agent import run_agent, READ_TOOLS

CVE = "CVE-2021-44228"


def _use(i: int, name: str, reason: str, **args) -> dict:
    return {"type": "tool_use", "id": f"tu_{name}_{i}", "name": name,
            "input": {**args, "reason": reason}}


def _results(messages: list) -> dict[str, dict]:
    """tool_use_id -> parsed JSON of the latest tool_result message."""
    out = {}
    for b in messages[-1]["content"]:
        try:
            out[b["tool_use_id"]] = json.loads(b["content"])
        except (json.JSONDecodeError, TypeError):
            out[b["tool_use_id"]] = None
    return out


def scripted(org: str):
    state: dict = {}

    def llm(system, messages, tools):
        turn = sum(1 for m in messages if m["role"] == "assistant")
        state["tools"] = [t["name"] for t in tools]
        if turn == 0:
            return [{"type": "text", "text": "Start with the CVE and its blast radius."},
                    _use(0, "get_cve", "need KEV status and the vulnerable purl", cve=CVE, org=org),
                    _use(0, "score_risk", "ranked affected services with paths", cve=CVE, org=org)], "tool_use"
        if turn == 1:
            ranked = _results(messages)["tu_score_risk_0"]["ranked"]
            state["top"], state["second"] = ranked[0], ranked[1]
            return [_use(1, "evaluate_rules", "which rules fire for the top-risk service",
                         cve=CVE, service=state["top"]["service"], org=org),
                    _use(1, "find_owner", "who to page for the top-risk service",
                         service=state["top"]["service"], org=org),
                    _use(1, "apply_change", "should be refused: mutation is not offered",
                         kind="add_endpoint")], "tool_use"
        if turn == 2:
            res = _results(messages)
            state["fired"] = res[f"tu_evaluate_rules_1"]["fired"]
            top = state["top"]
            calls = []
            if "create_ticket" in state["tools"]:
                tampered = copy.deepcopy(top["path"])
                tampered["edges"][0]["type"] = "CALLS"
                calls = [_use(2, "create_ticket", "act on the top service with its proof",
                              cve=CVE, service=top["service"], verdict="ACT_NOW",
                              rationale="scripted", proof_path=top["path"], org=org),
                         _use(3, "create_ticket", "tampered proof should be refused",
                              cve=CVE, service=top["service"], verdict="ACT_NOW",
                              rationale="scripted", proof_path=tampered, org=org)]
            if calls:
                return calls, "tool_use"
        from .triage import verdict_for
        right = verdict_for(state["fired"])[0]
        wrong = "SUPPRESS" if right != "SUPPRESS" else "ACT_NOW"
        return [_use(9, "submit_findings", "done", summary="scripted summary", findings=[
            {"service": state["top"]["service"], "verdict": right, "reason": "rules"},
            {"service": state["second"]["service"], "verdict": wrong, "reason": "no rules checked"},
            {"service": "ghost-svc", "verdict": "ACT_NOW", "reason": "hallucinated"}])], "tool_use"

    return llm, state


def main() -> None:
    fails: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        print(f"{'PASS' if cond else 'FAIL'} {name}" + (f" ({detail})" if detail else ""))
        if not cond:
            fails.append(name)

    for org in ("dev", "heldout"):
        llm, state = scripted(org)
        out = asyncio.run(run_agent(f"Triage {CVE}", org, cve=CVE, llm=llm))
        print(f"[{org}]")
        offered = set(out["tools_offered"])
        check("read tools discovered over MCP", READ_TOOLS <= offered, str(sorted(offered)))
        check("mutation/actions not offered by default",
              not offered & {"apply_change", "create_ticket", "notify_owner", "open_fix_pr"})
        check("stopped on submit", out["stop"] == "submitted", out["stop"])
        check("every step has a reason", all(s["reason"] for s in out["trace"]))
        bad = [s for s in out["trace"] if s["tool"] == "apply_change"]
        check("unoffered tool refused", len(bad) == 1 and bad[0]["is_error"])
        f = {x["service"]: x for x in out["findings"]}
        top, second = state["top"]["service"], state["second"]["service"]
        check("top verdict agrees with rules", f[top]["verdict_agrees"], f[top]["rule_verdict"])
        check("top proof verified in graph", f[top]["proof"]["verified"], f[top]["proof"]["detail"])
        check("unchecked verdict flagged", not f[second]["verdict_agrees"]
              and f[second]["rule_verdict"] is None)
        check("hallucinated service unproven", not f["ghost-svc"]["proof"]["verified"],
              f["ghost-svc"]["proof"]["detail"])

    llm, state = scripted("dev")
    out = asyncio.run(run_agent(f"Triage {CVE}", "dev", cve=CVE, allow_actions=True, llm=llm))
    print("[dev, actions]")
    acts = out["actions"]
    check("action tools offered with --allow-actions", "create_ticket" in out["tools_offered"])
    check("real proof accepted", len(acts) == 2 and acts[0]["result"]["accepted"],
          str(acts[0]["result"] if acts else None))
    check("tampered proof refused", len(acts) == 2 and not acts[1]["result"]["accepted"],
          str(acts[1]["result"].get("reason") if len(acts) == 2 else None))

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
