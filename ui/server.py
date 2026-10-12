"""Blast Radius web UI backend (Phase 6).

Stdlib-only HTTP server: serves the single-page UI and JSON APIs backed by
the same agent/MCP functions as everything else (no duplicated logic).

  python -m ui.server [--port 8765]

Routes:
  GET  /                        index.html (+ /app.js, /style.css)
  GET  /api/triage?cve=&org=    ranked, explained triage with proof paths
  GET  /api/compare?cve=&org=   simulated fixes + recommendation
  POST /api/act                 {cve, org?, verdicts?, with_pr?} proof-backed actions
  POST /api/refusal_drill       {cve, org?} deliberately tampered proof -> refusal
  GET  /api/decisions           recent Decision nodes
  GET  /api/action_log?n=100    tail of actions/log.jsonl (accepts + refusals)
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from agent.triage import triage
from agent.compare import compare_fixes
from agent.act import act
from mcp_server import graph
from mcp_server.server import create_ticket

UI_DIR = Path(__file__).resolve().parent
log = logging.getLogger("blast-radius.ui")


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
                    with_pr=bool(body.get("with_pr", False))))
            if url.path == "/api/refusal_drill":
                return _json(self, self._refusal_drill(
                    body["cve"], body.get("org", "dev")))
            return _json(self, {"error": f"unknown route {url.path}"}, 404)
        except KeyError as e:
            return _json(self, {"error": f"missing parameter {e}"}, 400)
        except ValueError as e:
            return _json(self, {"error": str(e)}, 400)
        except Exception as e:
            log.exception("POST %s failed", self.path)
            return _json(self, {"error": f"{type(e).__name__}: {e}"}, 500)

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
        p = UI_DIR.parent / "actions" / "log.jsonl"
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
