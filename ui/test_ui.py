"""UI backend acceptance: every JSON route + the Investigate SSE stream, against the
real FalkorDB and a real MCP stdio server (scripted LLM, no API key needed).
Actions run inside isolated_actions (temp log, Decision nodes cleaned up).

  python -m ui.test_ui
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from urllib.parse import quote

from ui import server
from agent.test_mcp_agent import scripted
from agent.testkit import isolated_actions

CVE = "CVE-2021-44228"
fails: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f" ({detail})" if detail else ""))
    if not cond:
        fails.append(name)


def main() -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def get(path: str):
        with urllib.request.urlopen(base + path, timeout=120) as r:
            return json.load(r)

    def post(path: str, body: dict):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.load(r)

    def sse(path: str) -> list[dict]:
        with urllib.request.urlopen(base + path, timeout=300) as r:
            return [json.loads(line[6:]) for line in r.read().decode().splitlines()
                    if line.startswith("data: ")]

    try:
        with urllib.request.urlopen(base + "/", timeout=10) as r:
            html = r.read().decode()
        check("index served", "Investigate with Claude" in html and "Blast map" in html)

        cves = get("/api/cves?org=dev")["cves"]
        check("cve list", CVE in {c["id"] for c in cves}, f"{len(cves)} cves")

        t = get(f"/api/triage?cve={CVE}&org=dev")
        reach = [r for r in t["results"] if r["reachable"]]
        check("triage has verified exposure routes",
              reach and all(r["exposure"]["verified"] for r in reach), f"{len(reach)} reachable")

        server.AGENT_LLM = None
        cfg = get("/api/config")
        if not cfg["agent_llm"]:
            ev = sse(f"/api/investigate?org=dev&cve={CVE}")
            check("investigate without key explains", ev and ev[-1]["type"] == "error"
                  and "ANTHROPIC_API_KEY" in ev[-1]["error"])

        ev = sse(f"/api/investigate?org=dev&cve={CVE}&planner=offline")
        done = ev[-1]
        check("offline planner runs without a key, labelled, all findings check out",
              done["type"] == "done" and done["planner"] == "offline"
              and len(done["findings"]) == len(t["results"])
              and all(f["verdict_agrees"] and f["proof"]["verified"] for f in done["findings"])
              and any(e["type"] == "text" and "no model" in e["text"] for e in ev),
              f"{len(done.get('findings', []))} findings")

        llm, state = scripted("dev")
        server.AGENT_LLM = llm
        check("config reports agent", get("/api/config")["agent_llm"])
        ev = sse(f"/api/investigate?org=dev&cve={CVE}&question={quote('Triage ' + CVE)}")
        kinds = [e["type"] for e in ev]
        steps = [e for e in ev if e["type"] == "step"]
        check("stream starts with tool discovery", kinds[0] == "start"
              and "score_risk" in ev[0]["tools_offered"])
        check("one live event per tool call, each with reason + digest",
              len(steps) >= 4 and all(s["reason"] for s in steps)
              and any(s["brief"] for s in steps), f"{len(steps)} steps")
        done = ev[-1]
        check("stream ends with checked findings", done["type"] == "done"
              and done["stop"] == "submitted" and done["findings"])
        top = state["top"]["service"]
        f = {x["service"]: x for x in done["findings"]}
        check("top finding approvable", f[top]["verdict_agrees"] and f[top]["proof"]["verified"])

        with isolated_actions(("dev",)) as log_path:
            out = post("/api/act", {"cve": CVE, "org": "dev", "services": [top]})
            check("approve acts only on approved services",
                  {a["service"] for a in out["actions"]} == {top} and not out["refusals"],
                  out["summary"])
            ds = [d for d in get("/api/decisions?org=dev")["decisions"] if d["service"] == top]
            check("decisions recorded in graph", len(ds) >= 2)
            drill = post("/api/refusal_drill", {"cve": CVE, "org": "dev"})
            check("refusal drill refused", drill["accepted"] is False, drill["reason"][:60])
            log = get("/api/action_log?n=50")["entries"]
            check("log isolated to temp file", log_path.exists()
                  and len(log) == len(log_path.read_text().strip().splitlines()))

        # live change: expose an unreachable service, adopt the vuln in a clean one
        post("/api/live_revert", {"org": "dev"})
        by = {r["service"]: r for r in t["results"]}
        hidden = next(r["service"] for r in t["results"]
                      if not r["reachable"] and r["tier"] == "critical")
        clean = next(s["name"] for s in get("/api/services?org=dev")["services"]
                     if s["name"] not in by)
        pred = post("/api/assess", {"service": hidden, "expose": "/live/x", "org": "dev"})
        check("sandbox predicts the flip without touching live",
              any(f["service"] == hidden and f["after"] == "ACT_NOW" for f in pred["findings"])
              and not get("/api/live?org=dev")["changes"])
        act = next(r["service"] for r in t["results"] if r["verdict"] == "ACT_NOW")
        pin = post("/api/assess", {"service": act, "adds": [t["cve"]["fixed_purl"]],
                                   "removes": [t["cve"]["vuln_purl"]], "org": "dev"})
        check("sandbox credits a pinned fix", not pin["findings"] and any(
            f["service"] == act and f["before"] == "ACT_NOW" for f in pin["resolved"]), act)
        try:
            post("/api/live", {"op": "expose", "service": hidden, "org": "dev"})
            post("/api/live", {"op": "adopt", "service": clean, "cve": CVE, "org": "dev"})
            check("live changes listed",
                  {c["kind"] for c in get("/api/live?org=dev")["changes"]} == {"expose", "adopt"})
            t2 = {r["service"]: r for r in
                  get(f"/api/triage?cve={CVE}&org=dev")["results"]}
            check("exposed service flips to ACT_NOW with a verified route",
                  by[hidden]["verdict"] == "SCHEDULE" and t2[hidden]["verdict"] == "ACT_NOW"
                  and t2[hidden]["exposure"]["verified"], hidden)
            check("adopting service joins the blast radius",
                  clean in t2 and t2[clean]["proof"]["verified"], clean)
            try:
                post("/api/live", {"op": "expose", "service": hidden, "org": "dev"})
                check("duplicate live change rejected", False)
            except urllib.error.HTTPError as e:
                check("duplicate live change rejected", e.code == 400)
        finally:
            r = post("/api/live_revert", {"org": "dev"})
        check("live changes reverted", r == {"org": "dev", "endpoints": 1, "dependencies": 1}
              and {x["service"] for x in get(f"/api/triage?cve={CVE}&org=dev")["results"]}
              == set(by))
    finally:
        server.AGENT_LLM = None
        srv.shutdown()

    print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
