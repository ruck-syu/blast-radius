"""Phase 5 actions + proof-path guardrail.

Every action tool takes proof_path (the serialized path from a read tool).
The guardrail: reject when missing; verify every edge exists in FalkorDB and
the endpoints match the claimed service (and CVE, when given); log the action
with its path; write a Decision node (ABOUT CVE/service, FIRED rules).

External delivery is env-gated: without GITHUB_TOKEN/DEMO_REPO (tickets/PRs)
or SLACK_WEBHOOK (notifications) actions run in dry-run mode — the guardrail,
Decision nodes, and log are still fully real. Live mode targets only our own
demo repo, never third-party repositories.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path

from . import graph

log = logging.getLogger("blast-radius.mcp")
ROOT = Path(__file__).resolve().parent.parent


def action_log_path() -> Path:
    """actions/log.jsonl, or BLAST_ACTION_LOG (tests point it at a temp file)."""
    return Path(os.getenv("BLAST_ACTION_LOG") or ROOT / "actions" / "log.jsonl")


def _append_log(entry: dict) -> None:
    path = action_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": int(time.time()), **entry}
    with path.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _verify_chain(org: str, path: dict | None) -> tuple[list[int], str]:
    """Chain integrity + every edge exists in FalkorDB. Returns (node ids, error or '')."""
    if not isinstance(path, dict) or not path.get("nodes"):
        return [], "refused: missing proof_path"
    nodes, edges = path["nodes"], path.get("edges") or []
    ids = [n["id"] for n in nodes]
    if len(ids) != len(edges) + 1:
        return [], "refused: malformed proof_path (nodes/edges mismatch)"
    for i, e in enumerate(edges):
        if e["from"] != ids[i] or e["to"] != ids[i + 1]:
            return [], f"refused: proof_path chain broken at edge {i}"
        rows, _ = graph.run(org, "verify_edge",
                            {"src": e["from"], "dst": e["to"], "rel": e["type"]})
        if not rows[0][0]:
            return [], (f"refused: proof edge {i} "
                        f"({e['from']})-[:{e['type']}]->({e['to']}) not in graph")
    return ids, ""


def verify_proof_path(org: str, proof_path: dict | None, service: str,
                      cve: str | None = None) -> tuple[bool, str, list[int]]:
    """Guardrail verification. Returns (ok, reason, node_id_list)."""
    ids, err = _verify_chain(org, proof_path)
    if err:
        return False, err, []
    rows, _ = graph.run(org, "verify_path_start", {"service": service, "nid": ids[0]})
    if not rows[0][0]:
        return False, f"refused: proof does not start at service {service!r}", []
    if cve is not None:
        rows, _ = graph.run(org, "verify_path_cve_anchor", {"cve": cve, "nid": ids[-1]})
        if not rows[0][0]:
            return False, f"refused: proof does not end at a package {cve} affects", []
    return True, "proof verified against graph", ids


def verify_exposure_path(org: str, path: dict | None,
                         service: str) -> tuple[bool, str]:
    """Exposure proof: public Endpoint -ROUTES_TO-> Service -CALLS*-> service, every edge in graph."""
    ids, err = _verify_chain(org, path)
    if err:
        return False, err.removeprefix("refused: ").replace("proof_path", "exposure path")
    rows, _ = graph.run(org, "verify_public_endpoint", {"nid": ids[0]})
    if not rows[0][0]:
        return False, "exposure path does not start at a public endpoint"
    rows, _ = graph.run(org, "verify_path_start", {"service": service, "nid": ids[-1]})
    if not rows[0][0]:
        return False, f"exposure path does not end at service {service!r}"
    return True, "public route verified against graph"


def _decision_id(action: str, cve: str, service: str) -> str:
    slug = f"{cve}-{service}-{action}".lower().replace("/", "-").replace(":", "-")
    return f"dec-{slug}-{int(time.time())}"


def _write_decision(org: str, action: str, cve: str, service: str, verdict: str,
                    rationale: str, proof_ids: list[int], rules: list[str],
                    target: str) -> str:
    did = _decision_id(action, cve, service)
    rows, _ = graph.run(org, "write_decision", {
        "id": did, "timestamp": int(time.time()), "verdict": verdict,
        "rationale": rationale, "proof_ids": proof_ids, "action": action,
        "target": target, "cve": cve, "service": service, "rules": rules})
    return rows[0][0]


def _github_issue(title: str, body: str) -> tuple[str, str]:
    """Returns (mode, url_or_note). Live only with GITHUB_TOKEN + DEMO_REPO."""
    token, repo = os.getenv("GITHUB_TOKEN"), os.getenv("DEMO_REPO")
    if not token or not repo:
        return "dry-run", "no GITHUB_TOKEN/DEMO_REPO; issue payload logged locally"
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/issues",
        data=json.dumps({"title": title, "body": body}).encode(),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return "live", json.load(resp).get("html_url", "")


def _slack_notify(text: str, channel: str) -> tuple[str, str]:
    webhook = os.getenv("SLACK_WEBHOOK")
    if not webhook:
        return "dry-run", f"no SLACK_WEBHOOK; notification for {channel} logged locally"
    req = urllib.request.Request(
        webhook, data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return "live", f"slack http {resp.status}"


def _act(org: str, action: str, cve: str, service: str, verdict: str,
         rationale: str, proof_path: dict | None, rules: list[str],
         deliver, precheck=None) -> dict:
    """Shared guardrail + Decision + delivery wrapper. Returns accept/refuse.
    `precheck` (after the proof check) returns (ok, reason, extra fields) and can
    refuse the action; `deliver` then receives the extra fields."""
    t0 = time.time()
    ok, reason, ids = verify_proof_path(org, proof_path, service,
                                        cve if action in ("ticket", "fix_pr") else None)
    base = {"action": action, "cve": cve, "service": service, "org": org,
            "proof_ids": ids}
    if not ok:
        log.warning("refusal action=%s cve=%s service=%s: %s", action, cve, service, reason)
        _append_log({**base, "accepted": False, "reason": reason})
        return {"accepted": False, "reason": reason,
                "latency_ms": round((time.time() - t0) * 1000, 1)}
    extra = {}
    if precheck:
        ok, reason, extra = precheck()
        if not ok:
            log.warning("refusal action=%s cve=%s service=%s: %s", action, cve, service, reason)
            _append_log({**base, "accepted": False, "reason": reason})
            return {"accepted": False, "reason": reason, **extra,
                    "latency_ms": round((time.time() - t0) * 1000, 1)}
    try:
        mode, target = deliver(**extra)
    except Exception as e:
        reason = f"delivery failed: {e}"
        log.warning("action=%s cve=%s service=%s: %s", action, cve, service, reason)
        _append_log({**base, "accepted": False, "reason": reason})
        return {"accepted": False, "reason": reason,
                "latency_ms": round((time.time() - t0) * 1000, 1)}
    did = _write_decision(org, action, cve, service, verdict, rationale, ids, rules, target)
    _append_log({**base, "accepted": True, "mode": mode, "target": target,
                 "decision_id": did, "verdict": verdict})
    log.info("action=%s decision=%s mode=%s", action, did, mode)
    return {"accepted": True, "mode": mode, "target": target, "decision_id": did,
            "proof_ids": ids, **extra, "latency_ms": round((time.time() - t0) * 1000, 1)}


def create_ticket(cve: str, service: str, verdict: str, rationale: str,
                  proof_path: dict | None, rules: list[str] | None = None,
                  org: str = "dev") -> dict:
    """Open a ticket on our demo repo (env-gated live, else dry-run). Requires proof_path."""
    rules = rules or []
    title = f"[{verdict}] {cve} affects {service}"
    body = (f"{rationale}\n\nFired rules: {', '.join(rules)}\n"
            f"Proof node ids: {(proof_path or {}).get('nodes') and [n['id'] for n in proof_path['nodes']]}\n"
            f"Summary: {(proof_path or {}).get('summary', '')}")
    return _act(org, "ticket", cve, service, verdict, rationale, proof_path, rules,
                lambda: _github_issue(title, body))


def notify_owner(cve: str, service: str, verdict: str, rationale: str,
                 proof_path: dict | None, channel: str = "",
                 rules: list[str] | None = None, org: str = "dev") -> dict:
    """Notify the owning team (Slack webhook when configured). Requires proof_path."""
    text = f"[{verdict}] {cve} affects {service}: {rationale}"
    return _act(org, "notify", cve, service, verdict, rationale, proof_path, rules or [],
                lambda: _slack_notify(text, channel or "#unspecified"))


def open_fix_pr(cve: str, service: str, verdict: str, rationale: str,
                proof_path: dict | None, fix: str = "",
                rules: list[str] | None = None, org: str = "dev") -> dict:
    """Propose a fix PR on our demo repo (dry-run until a demo checkout exists).

    Second guardrail after the proof check: the upgrade (service pins `fix`, or
    the CVE's fixed version, and stops resolving the vulnerable one) is applied
    to a sandbox graph copy first. Refused unless it resolves this CVE for this
    service and opens no new ACT_NOW exposure; the sandbox result goes in the PR,
    with a warning when the target version still carries other CVEs.

    Live PR creation needs a demo-repo checkout to branch from, so the fix
    payload (upgrade + proof + sandbox check) is logged and a Decision node is
    still written. Never touches third-party repositories.
    """
    def precheck():
        rows, _ = graph.run(org, "get_cve", {"cve": cve})
        vuln = rows[0][5] if rows else None
        fixed = fix if fix.startswith("pkg:") else (rows[0][6] if rows else None)
        if not vuln or not fixed or fixed == vuln:
            return False, f"refused: no fixed version of {cve} in the graph to verify", {}
        from .assess import assess_change
        r = assess_change(service, [fixed], "", org, [vuln])
        check = {"upgrade": {"from": vuln, "to": fixed}, "unknown": r["unknown_packages"],
                 "resolves": [f"{x['cve']} on {x['service']} (was {x['before']})"
                              for x in r["resolved"]],
                 "new_exposure": [f"{x['cve']} on {x['service']} -> {x['after']}"
                                  for x in r["findings"]],
                 "still_exposed": [f"{x['cve']} ({x['verdict']})" for x in r["carried"]],
                 "latency_ms": r["latency_ms"]}
        if not any(x["cve"] == cve and x["service"] == service and x["after"] is None
                   for x in r["resolved"]):
            return False, (f"refused: sandbox upgrade to {fixed} does not resolve {cve} "
                           f"for {service}"), {"fix_check": check}
        if r["worst"] == "ACT_NOW":
            return False, (f"refused: sandbox upgrade to {fixed} opens new ACT_NOW exposure: "
                           + "; ".join(check["new_exposure"])), {"fix_check": check}
        return True, "", {"fix_check": check}

    def deliver(fix_check):
        u = fix_check["upgrade"]
        payload = (f"FIX PR draft for {service}: {u['from']} -> {u['to']} ({cve}). "
                   f"Sandbox check ({fix_check['latency_ms']:.0f} ms): resolves "
                   f"{'; '.join(fix_check['resolves'])}; new exposure: "
                   f"{'; '.join(fix_check['new_exposure']) or 'none'}. "
                   + (f"Warning: {u['to']} is itself affected by "
                      f"{', '.join(fix_check['still_exposed'])}; a later version is needed "
                      "to clear those. " if fix_check["still_exposed"] else "")
                   + rationale)
        return "dry-run", f"demo checkout not configured; {payload}"

    return _act(org, "fix_pr", cve, service, verdict, rationale, proof_path, rules or [],
                deliver, precheck)
