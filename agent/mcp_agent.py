"""MCP agent: Claude selects graph tools over MCP to answer a triage question.

Unlike agent/triage.py (fixed plan, direct function calls), this agent is an
MCP *client*: it spawns mcp_server.server over stdio, discovers the tools via
list_tools, and lets the model decide which tool to call next from what the
graph has shown so far. Guardrails stay in code:

  - every tool call must carry a `reason` (logged in the trace, stripped
    before the MCP call), so each step of the multi-hop walk is explained;
  - apply_change (graph mutation) is never exposed; action tools only with
    --allow-actions, and the server-side proof-path guardrail still applies;
  - the model ends by calling submit_findings; each verdict is then re-derived
    from the evaluate_rules output it saw (verdict_for), and the dependency path
    the tools returned for that service is re-verified edge by edge against
    FalkorDB. Disagreements and unproven services are flagged.

Usage:
  python -m agent.mcp_agent CVE-2021-44228 [--org dev] [--allow-actions] [--json]
  python -m agent.mcp_agent --question "Which public services ..." [--org heldout]
  python -m agent.mcp_agent CVE-2021-44228 --offline   # no key: fixed-policy planner, not a model

Config: ANTHROPIC_API_KEY (or an `ant auth login` profile), LLM_MODEL
(default claude-opus-5-5), LLM_EFFORT (default medium).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Callable

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

from mcp_server.actions import verify_proof_path
from .triage import verdict_for

ROOT = Path(__file__).resolve().parent.parent
MAX_TURNS = 30

READ_TOOLS = {"get_cve", "find_affected_services", "check_reachability", "dependency_path",
              "rank_criticality", "find_owner", "score_risk", "evaluate_rules", "simulate_fix",
              "assess_change"}
ACTION_TOOLS = {"create_ticket", "notify_owner", "open_fix_pr"}

SYSTEM = """You are Blast Radius, a software supply-chain triage agent. Your only view \
of the organisation is a FalkorDB graph (CVE -AFFECTS-> Package -DEPENDS_ON*-> Package \
<-USES- Service; Endpoint -ROUTES_TO-> Service -CALLS*-> Service; Service -OWNED_BY-> \
Team), reached through the tools provided. Work out what you need, call the tool that \
answers it, and let each result decide your next step. Don't call a tool whose answer \
you already have. Every tool call takes a `reason`: one sentence on why this call, \
citing what earlier results showed.

Verdicts follow named rules that evaluate_rules computes in the graph, and code \
re-checks them: ACT_NOW when R_PUBLIC_REACH fires together with R_KEV or \
R_CRITICAL_TIER; SUPPRESS when R_NO_REACH fires and R_KEV does not; otherwise \
SCHEDULE. Only give a verdict for a service after calling evaluate_rules for it.

When you have the answer, call submit_findings exactly once. Code attaches to each \
reported service the dependency path a read tool returned for it (score_risk, \
find_affected_services or dependency_path) and verifies it edge by edge against the \
graph, so only report services whose path you have retrieved."""

ACTIONS_NOTE = """

You may act: for ACT_NOW services only, open a ticket (create_ticket) and notify the \
owning team (notify_owner), passing the same proof_path object a read tool returned. \
Actions with a missing or altered proof are refused by the server."""

SUBMIT_TOOL = {
    "name": "submit_findings",
    "description": "Submit the final triage answer. Call exactly once, after the evidence is gathered.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string",
                        "description": "2-4 sentences answering the question for a security engineer."},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "service": {"type": "string"},
                        "verdict": {"type": "string", "enum": ["ACT_NOW", "SCHEDULE", "SUPPRESS"]},
                        "reason": {"type": "string",
                                   "description": "Why, citing rules fired, reachability, and path."},
                    },
                    "required": ["service", "verdict", "reason"],
                },
            },
        },
        "required": ["summary", "findings"],
    },
}


def to_claude_tools(mcp_tools, allowed: set[str]) -> list[dict]:
    """MCP tool list -> Claude tool defs, each with a required `reason` argument."""
    tools = []
    for t in mcp_tools:
        if t.name not in allowed:
            continue
        schema = json.loads(json.dumps(t.inputSchema))
        schema.setdefault("properties", {})["reason"] = {
            "type": "string", "description": "Why this call, given what you have seen so far."}
        schema["required"] = [*schema.get("required", []), "reason"]
        tools.append({"name": t.name, "description": t.description or "", "input_schema": schema})
    return tools + [SUBMIT_TOOL]


def claude_llm(model: str | None = None, effort: str | None = None) -> Callable:
    """Returns llm(system, messages, tools) -> (content_dicts, stop_reason)."""
    import anthropic  # lazy: optional dependency, offline tests use a scripted llm

    client = anthropic.Anthropic()
    model = model or os.getenv("LLM_MODEL", "claude-opus-5-5")
    effort = effort or os.getenv("LLM_EFFORT", "medium")

    def call(system: str, messages: list, tools: list) -> tuple[list[dict], str]:
        resp = client.beta.messages.create(
            model=model, max_tokens=16000, system=system, tools=tools,
            messages=messages, output_config={"effort": effort},
            betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        return [b.to_dict() for b in resp.content], resp.stop_reason

    return call


def _brief(tool: str, r: dict | None) -> str:
    """One-line digest of a tool result for the live trace."""
    if not isinstance(r, dict):
        return ""
    if tool == "get_cve":
        return (f"cvss {r.get('cvss')}, KEV {r.get('in_kev')}, {r.get('vuln_purl')}"
                if r.get("found") else "unknown CVE")
    if tool == "score_risk" and r.get("ranked"):
        top = r["ranked"][0]
        return (f"{r['count']} services, {sum(x['reachable'] for x in r['ranked'])} reachable; "
                f"top {top['service']} risk {top['risk']}")
    if tool == "find_affected_services":
        return f"{r.get('count', 0)} affected services"
    if tool == "check_reachability":
        return (f"reachable via {r['entries'][0]['entry_point']} ({len(r['entries'])} routes)"
                if r.get("reachable") else "no public route")
    if tool == "dependency_path":
        return (f"depth {r['dependency']['depth']}" if r.get("affected") else "not affected")
    if tool == "evaluate_rules":
        return "fired: " + (", ".join(r.get("fired", [])) or "none")
    if tool == "find_owner":
        return f"{r.get('team')} ({r.get('slack_channel')})" if r.get("found") else "no owner"
    if tool == "rank_criticality" and r.get("ranking"):
        return "top: " + ", ".join(x["service"] for x in r["ranking"][:3])
    if tool == "simulate_fix" and r.get("reduction"):
        return f"risk reduction {r['reduction'].get('total_risk')}"
    if tool == "assess_change":
        f = r.get("findings", [])
        return ((f"{len(f)} verdicts worse, worst {r.get('worst')}" if f
                 else "no new exposure")
                + (f"; resolves {len(r['resolved'])}" if r.get("resolved") else "")
                + (f"; unknown {r['unknown_packages']}" if r.get("unknown_packages") else ""))
    if "accepted" in r:
        return "accepted" if r["accepted"] else f"REFUSED: {r.get('reason')}"
    return ""


def _short_args(args: dict) -> dict:
    return {k: ("<proof_path>" if k == "proof_path" else v) for k, v in args.items()}


def _paths_by_service(trace: list[dict]) -> dict[str, dict]:
    """Proof paths the tools actually returned, keyed by service (first seen wins)."""
    out: dict[str, dict] = {}
    for step in trace:
        r = step.get("result") or {}
        for item in r.get("ranked", []) + r.get("services", []):
            if item.get("path"):
                out.setdefault(item["service"], item["path"])
        if r.get("dependency"):
            out.setdefault(r["service"], r["dependency"]["path"])
    return out


def check_findings(submitted: dict, trace: list[dict], org: str, cve: str | None) -> list[dict]:
    """Re-derive each verdict from evaluate_rules results and verify each proof in the graph."""
    fired_by_service = {s["result"]["service"]: s["result"]["fired"] for s in trace
                        if s["tool"] == "evaluate_rules" and not s["is_error"]}
    paths = _paths_by_service(trace)
    checked = []
    for f in submitted.get("findings", []):
        svc = f.get("service", "")
        fired = fired_by_service.get(svc)
        rule_verdict = verdict_for(fired)[0] if fired is not None else None
        proof = paths.get(svc)
        ok, detail, _ = verify_proof_path(org, proof, svc, cve)
        checked.append({
            "service": svc, "verdict": f.get("verdict"), "reason": f.get("reason"),
            "rules_fired": fired, "rule_verdict": rule_verdict,
            "verdict_agrees": rule_verdict == f.get("verdict"),
            "proof": {"verified": ok, "detail": detail,
                      "summary": (proof or {}).get("summary")},
        })
    return checked


async def run_agent(question: str, org: str = "dev", cve: str | None = None,
                    allow_actions: bool = False, llm: Callable | None = None,
                    max_turns: int = MAX_TURNS, verbose: bool = False,
                    on_event: Callable[[dict], None] | None = None) -> dict:
    """on_event (optional) receives start/text/step events as they happen (UI streaming)."""
    t0 = time.time()
    emit = on_event or (lambda _e: None)
    llm = llm or claude_llm()
    allowed = READ_TOOLS | (ACTION_TOOLS if allow_actions else set())
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_server.server"],
                                   cwd=str(ROOT), env=dict(os.environ))
    errlog = sys.stderr if verbose else open(os.devnull, "w")
    trace: list[dict] = []
    submitted, final_text, stop = None, "", "max_turns"

    try:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                tools = to_claude_tools(listed.tools, allowed)
                system = SYSTEM + (ACTIONS_NOTE if allow_actions else "")
                focus = f"CVE in focus: {cve}.\n" if cve and cve not in question else ""
                messages: list[dict] = [{"role": "user", "content":
                                         f"Org graph: {org}.\n{focus}\n{question}"}]
                emit({"type": "start", "tools_offered": sorted(t["name"] for t in tools)})

                for _ in range(max_turns):
                    content, stop_reason = await asyncio.to_thread(llm, system, messages, tools)
                    messages.append({"role": "assistant", "content": content})
                    for b in content:
                        if b.get("type") == "text" and b.get("text", "").strip():
                            emit({"type": "text", "text": b["text"]})
                    if stop_reason == "pause_turn":
                        continue
                    if stop_reason in ("refusal", "max_tokens"):
                        stop = stop_reason
                        break
                    uses = [b for b in content if b.get("type") == "tool_use"]
                    if not uses:
                        final_text = " ".join(b["text"] for b in content if b.get("type") == "text")
                        stop = "end_turn"
                        break

                    results = []
                    for u in uses:
                        args = dict(u.get("input") or {})
                        reason = args.pop("reason", "")
                        if u["name"] == "submit_findings":
                            submitted = args
                            results.append({"type": "tool_result", "tool_use_id": u["id"],
                                            "content": "recorded"})
                            continue
                        step = {"step": len(trace) + 1, "tool": u["name"],
                                "args": _short_args(args), "reason": reason}
                        if u["name"] not in allowed:
                            text, is_error, parsed = f"tool {u['name']!r} is not available", True, None
                        else:
                            ts = time.time()
                            res = await session.call_tool(u["name"], args)
                            step["latency_ms"] = round((time.time() - ts) * 1000, 1)
                            text = "".join(c.text for c in res.content if c.type == "text")
                            is_error = bool(res.isError)
                            try:
                                parsed = json.loads(text)
                            except json.JSONDecodeError:
                                parsed = None
                        step.update(is_error=is_error, result=parsed,
                                    error=text if is_error else None,
                                    brief=text if is_error else _brief(u["name"], parsed))
                        trace.append(step)
                        emit({"type": "step", **{k: v for k, v in step.items() if k != "result"}})
                        results.append({"type": "tool_result", "tool_use_id": u["id"],
                                        "content": text, "is_error": is_error})
                    messages.append({"role": "user", "content": results})
                    if submitted is not None:
                        stop = "submitted"
                        break
    finally:
        if errlog is not sys.stderr:
            errlog.close()

    findings = check_findings(submitted, trace, org, cve) if submitted else []
    return {
        "question": question, "org": org, "stop": stop,
        "summary": (submitted or {}).get("summary") or final_text,
        "findings": findings,
        "tools_offered": sorted(t["name"] for t in tools),
        "trace": [{k: v for k, v in s.items() if k != "result"} for s in trace],
        "actions": [s for s in trace if s["tool"] in ACTION_TOOLS],
        "total_latency_ms": round((time.time() - t0) * 1000, 1),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Claude picks graph tools over MCP to triage.")
    ap.add_argument("cve", nargs="?", help="CVE ID to triage, e.g. CVE-2021-44228")
    ap.add_argument("--question", help="free-form question instead of a CVE triage")
    ap.add_argument("--org", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--allow-actions", action="store_true",
                    help="expose create_ticket/notify_owner/open_fix_pr (guardrail still enforced)")
    ap.add_argument("--max-turns", type=int, default=MAX_TURNS)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verbose", action="store_true", help="show MCP server logs")
    ap.add_argument("--offline", action="store_true",
                    help="no model: a fixed rule-following planner drives the same MCP loop")
    args = ap.parse_args()
    if not args.cve and not args.question:
        ap.error("give a CVE ID or --question")
    llm = None
    if args.offline:
        from .offline_planner import offline_llm
        llm = offline_llm(args.cve, args.org)
    question = args.question or (
        f"Triage {args.cve}: which services are affected, which are reachable from a "
        f"public endpoint, what verdict does each get, and who owns the ones to act on now?")

    try:
        out = asyncio.run(run_agent(question, args.org, cve=args.cve,
                                    allow_actions=args.allow_actions, llm=llm,
                                    max_turns=args.max_turns, verbose=args.verbose))
    except BaseExceptionGroup as eg:  # MCP client task groups wrap the real error
        while isinstance(eg, BaseExceptionGroup):
            eg = eg.exceptions[0]
        raise SystemExit(f"mcp_agent failed: {type(eg).__name__}: {eg}")
    if args.json:
        print(json.dumps(out, indent=2))
        return
    print(f"Tools offered over MCP: {', '.join(out['tools_offered'])}\n")
    for s in out["trace"]:
        flag = " ERROR" if s["is_error"] else ""
        print(f"{s['step']:2d}. {s['tool']}({json.dumps(s['args'])}){flag}")
        print(f"    why: {s['reason']}")
        if s.get("brief"):
            print(f"    got: {s['brief']}")
    print(f"\n[{out['stop']}, {len(out['trace'])} tool calls, {out['total_latency_ms']:.0f}ms]")
    print(out["summary"])
    for f in out["findings"]:
        agree = "agrees" if f["verdict_agrees"] else f"DISAGREES (rules say {f['rule_verdict']})"
        proof = "OK " if f["proof"]["verified"] else "BAD"
        print(f"  [{f['verdict']:8s}][{proof}] {f['service']}: verdict {agree}")
        print(f"      proof: {f['proof']['summary'] or f['proof']['detail']}")
        print(f"      {f['reason']}")


if __name__ == "__main__":
    main()
