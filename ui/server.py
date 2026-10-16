"""Blast Radius web UI backend (Phase 6).

Stdlib-only HTTP server: serves the single-page UI and JSON APIs backed by
the same agent/MCP functions as everything else (no duplicated logic).

  python -m ui.server [--port 8765]

Routes:
  GET  /                        index.html (+ /app.js, /style.css)
  GET  /api/triage?cve=&org=    ranked, explained triage with proof paths
  GET  /api/compare?cve=&org=   simulated fixes + recommendation
  POST /api/act                 {cve, org?, verdicts?, with_pr?, services?} proof-backed actions
  POST /api/refusal_drill       {cve, org?} deliberately tampered proof -> refusal
  GET  /api/decisions?org=      recent Decision nodes
  GET  /api/cves?org=           CVEs in the org graph (id, cvss, KEV, summary)
  GET  /api/config              which optional live wires are configured
  GET  /api/investigate?question=&org=&cve=
                                Server-Sent Events: Claude picks MCP tools (agent.mcp_agent),
                                one event per tool call with its reason, then checked findings
  GET  /api/action_log?n=100    tail of the action log (accepts + refusals)
  GET  /api/services?org=       every service (name, tier)
  GET  /api/posture?org=        every CVE rolled up by service and vulnerable package
  GET  /api/live?org=           live changes currently applied (agent.live)
  POST /api/live                {op: expose|adopt, service, cve?, org?} mutate the live graph
  POST /api/live_revert         {org?} remove every live change
  POST /api/assess              {service, adds?, expose?, org?} pre-merge check in a sandbox copy
  POST /api/import_cve          {id, org?} fetch an advisory from OSV.dev into the graph (ingest.osv)
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from agent.triage import triage
from ingest import osv
from mcp_server.posture import org_posture
from agent.compare import compare_fixes
from agent.act import act
from agent import live
from mcp_server import graph
from mcp_server.server import create_ticket
from mcp_server.actions import action_log_path
from mcp_server.server import get_cve
from mcp_server.assess import assess_change
from mcp_server.simulate import list_cves
from ingest.config import graph_name

UI_DIR = Path(__file__).resolve().parent
log = logging.getLogger("blast-radius.ui")

# Tests inject a scripted llm here; otherwise Investigate needs ANTHROPIC_API_KEY.
AGENT_LLM = None


def agent_available() -> bool:
    return AGENT_LLM is not None or bool(os.getenv("ANTHROPIC_API_KEY"))


def _json(handler: BaseHTTPRequestHandler, obj: object, status: int = 200) -> None:
    body = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "BlastRadiusUI/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quieter logging
        log.info("%s %s", self.address_string(), fmt % args)

    def _send_static(self, name: str, ctype: str) -> None:
        path = UI_DIR / name
        if not path.exists():
            return _json(self, {"error": f"no such file {name}"}, 404)
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return {}
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        try:
            if url.path in ("/", "/index.html"):
                return self._send_static("index.html", "text/html")
            if url.path == "/app.js":
                return self._send_static("app.js", "application/javascript")
            if url.path == "/style.css":
                return self._send_static("style.css", "text/css")
            if url.path == "/api/triage":
                return _json(self, triage(qs["cve"][0], qs.get("org", ["dev"])[0],
                                          use_llm=False))
            if url.path == "/api/compare":
                return _json(self, compare_fixes(qs["cve"][0], qs.get("org", ["dev"])[0]))
            if url.path == "/api/decisions":
                rows, _ = graph.run(qs.get("org", ["dev"])[0], "list_decisions", {})
                return _json(self, {"decisions": [
                    {"id": r[0], "ts": r[1], "action": r[2], "verdict": r[3],
                     "target": r[4], "cve": r[5], "service": r[6], "rules": r[7]}
                    for r in rows]})
            if url.path == "/api/cves":
                org = qs.get("org", ["dev"])[0]
                cves = [get_cve(c, org) for c in list_cves(graph_name(org))]
                return _json(self, {"cves": [
                    {"id": c["id"], "cvss": c["cvss"], "in_kev": c["in_kev"],
                     "summary": c["summary"]} for c in cves if c["found"]]})
            if url.path == "/api/config":
                return _json(self, {
                    "agent_llm": agent_available(),
                    "model": os.getenv("LLM_MODEL", "claude-opus-5-5"),
                    "github_live": bool(os.getenv("GITHUB_TOKEN") and os.getenv("DEMO_REPO")),
                    "slack_live": bool(os.getenv("SLACK_WEBHOOK"))})
            if url.path == "/api/investigate":
                return self._investigate(qs)
            if url.path == "/api/posture":
                return _json(self, org_posture(qs.get("org", ["dev"])[0],
                                               int(qs.get("limit", ["10"])[0])))
            if url.path == "/api/services":
                return _json(self, {"services": live.services(qs.get("org", ["dev"])[0])})
            if url.path == "/api/live":
                return _json(self, {"changes": live.list_changes(qs.get("org", ["dev"])[0])})
            if url.path == "/api/action_log":
                return _json(self, {"entries": self._log_tail(int(qs.get("n", ["100"])[0]))})
            return _json(self, {"error": f"unknown route {url.path}"}, 404)
        except KeyError as e:
            return _json(self, {"error": f"missing parameter {e}"}, 400)
        except ValueError as e:
            return _json(self, {"error": str(e)}, 400)
        except Exception as e:  # never leak a traceback-shaped 500 without message
            log.exception("GET %s failed", self.path)
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)

    def do_POST(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        body = self._body()
        try:
            if url.path == "/api/act":
                return _json(self, act(
                    body["cve"], body.get("org", "dev"),
                    verdicts=tuple(body.get("verdicts", ["ACT_NOW"])),
                    with_pr=bool(body.get("with_pr", False)),
                    services=body.get("services")))
            if url.path == "/api/refusal_drill":
                return _json(self, self._refusal_drill(
                    body["cve"], body.get("org", "dev")))
            if url.path == "/api/live":
                org, op = body.get("org", "dev"), body["op"]
                if op == "expose":
                    return _json(self, live.expose(body["service"], org))
                if op == "adopt":
                    return _json(self, live.adopt(body["service"], body["cve"], org))
                raise ValueError(f"unknown live op {op!r} (expose|adopt)")
            if url.path == "/api/assess":
                return _json(self, assess_change(body["service"], body.get("adds") or [],
                                                 body.get("expose") or "",
                                                 body.get("org", "dev"),
                                                 body.get("removes") or []))
            if url.path == "/api/live_revert":
                return _json(self, live.revert(body.get("org", "dev")))
            if url.path == "/api/import_cve":
                org = body.get("org", "dev")
                graph_name(org)
                try:
                    rec = osv.fetch_record(body["id"].strip())
                except OSError as e:
                    return _json(self, {"error": f"OSV.dev: {e}"}, 502)
                p = osv.write(osv.plan(rec, org))
                return _json(self, {**p, "text": osv.describe(p)})
            return _json(self, {"error": f"unknown route {url.path}"}, 404)
        except KeyError as e:
            return _json(self, {"error": f"missing parameter {e}"}, 400)
        except ValueError as e:
            return _json(self, {"error": str(e)}, 400)
        except Exception as e:
            log.exception("POST %s failed", self.path)
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)

    def _investigate(self, qs: dict) -> None:
        """Stream agent.mcp_agent events as SSE; the final event carries checked findings."""
        org = qs.get("org", ["dev"])[0]
        cve = (qs.get("cve", [""])[0] or "").strip() or None
        question = (qs.get("question", [""])[0] or "").strip()
        graph_name(org)  # ValueError -> 400 for unknown org
        if not question:
            if not cve:
                raise ValueError("give a question or a cve")
            question = (f"Triage {cve}: which services are affected, which are reachable "
                        f"from a public endpoint, what verdict does each get, and who owns "
                        f"the ones to act on now?")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def send(event: dict) -> None:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
            self.wfile.flush()

        offline = qs.get("planner", [""])[0] == "offline"
        if not offline and not agent_available():
            send({"type": "error", "error": "ANTHROPIC_API_KEY is not set: add it to .env "
                  "and restart the UI to let Claude investigate, or run the offline planner."})
            return
        from agent.mcp_agent import run_agent
        llm = AGENT_LLM
        if offline:
            from agent.offline_planner import offline_llm
            llm = offline_llm(cve, org)
        try:
            out = asyncio.run(run_agent(question, org, cve=cve, llm=llm, on_event=send))
            send({"type": "done", "planner": "offline" if offline else "claude", **out})
        except (BrokenPipeError, ConnectionResetError):
            log.info("investigate client disconnected")
        except BaseException as e:  # noqa: BLE001 - MCP task groups wrap the real error
            while isinstance(e, BaseExceptionGroup):
                e = e.exceptions[0]
            log.exception("investigate failed")
            try:
                send({"type": "error", "error": f"{type(e).__name__}: {e}"})
            except OSError:
                pass

    @staticmethod
    def _refusal_drill(cve: str, org: str) -> dict:
        """Tamper with a real proof and submit it: must come back refused."""
        out = triage(cve, org, use_llm=False)
        if not out["known_cve"] or not out["results"]:
            return {"accepted": True, "drill": "no-affected-services",
                    "reason": "nothing to tamper with"}
        item = out["results"][0]
        forged = copy.deepcopy(item["proof"]["path"])
        forged["edges"][0]["type"] = "CALLS"  # consistent ids, edge does not exist
        res = create_ticket(cve, item["service"], item["verdict"], "refusal drill",
                            forged, item["rules_fired"], org)
        return {"drill": "forged-edge-type", "service": item["service"],
                "accepted": res["accepted"],
                "reason": res.get("reason", res.get("decision_id", ""))}

    @staticmethod
    def _log_tail(n: int) -> list[dict]:
        p = action_log_path()
        if not p.exists():
            return []
        lines = p.read_text().strip().split("\n")
        return [json.loads(line) for line in lines[-max(n, 1):] if line.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Blast Radius UI on http://127.0.0.1:{args.port}  (Ctrl-C to stop)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
