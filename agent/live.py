"""Live graph changes for the demo: mutate the live graph, re-triage, revert.

Two what-ifs, both through apply_change (no retraining, no reload):
  expose  a public endpoint now routes to a service (reachability changes)
  adopt   a service starts using the CVE's vulnerable package (blast radius grows)

Every change is tagged `source: "live-demo"` so revert removes exactly these.

  python -m agent.live expose d-recommend-api [--org dev]
  python -m agent.live adopt d-search-api --cve CVE-2021-44228
  python -m agent.live list | revert
"""
from __future__ import annotations

import argparse
import json
import re

from mcp_server import graph
from mcp_server.apply import apply_change
from mcp_server.server import get_cve

SOURCE = "live-demo"


def list_changes(org: str = "dev") -> list[dict]:
    rows, _ = graph.run(org, "list_live_changes", {"source": SOURCE})
    return [{"kind": r[0], "what": r[1], "service": r[2]} for r in rows]


def services(org: str = "dev") -> list[dict]:
    rows, _ = graph.run(org, "list_services", {})
    return [{"name": r[0], "tier": r[1]} for r in rows]


def expose(service: str, org: str = "dev") -> dict:
    """Route a new public endpoint straight to `service`."""
    path = "/live/" + re.sub(r"[^a-z0-9-]", "-", service.lower())
    if any(c["kind"] == "expose" and c["service"] == service for c in list_changes(org)):
        raise ValueError(f"{service} is already exposed by a live change")
    out = apply_change("add_endpoint", org, service=service, path=path, public=True,
                       source=SOURCE)
    return {**out, "summary": f"public endpoint {path} now routes to {service}"}


def adopt(service: str, cve: str, org: str = "dev") -> dict:
    """Make `service` depend directly on the package `cve` affects."""
    c = get_cve(cve, org)
    if not c["found"]:
        raise ValueError(f"{cve} is not in the {org} graph")
    if any(c2["kind"] == "adopt" and c2["service"] == service and c2["what"] == c["vuln_purl"]
           for c2 in list_changes(org)):
        raise ValueError(f"{service} already adopted {c['vuln_purl']} in a live change")
    out = apply_change("add_dependency", org, service=service, purl=c["vuln_purl"],
                       source=SOURCE)
    return {**out, "summary": f"{service} now uses {c['vuln_purl']}"}


def revert(org: str = "dev") -> dict:
    eps, _ = graph.run(org, "revert_live_endpoints", {"source": SOURCE})
    deps, _ = graph.run(org, "revert_live_dependencies", {"source": SOURCE})
    return {"org": org, "endpoints": eps[0][0], "dependencies": deps[0][0]}


def main() -> None:
    ap = argparse.ArgumentParser(description="live graph changes for the demo")
    ap.add_argument("op", choices=["expose", "adopt", "list", "revert"])
    ap.add_argument("service", nargs="?")
    ap.add_argument("--cve", default="CVE-2021-44228")
    ap.add_argument("--org", default="dev")
    a = ap.parse_args()
    if a.op in ("expose", "adopt") and not a.service:
        ap.error(f"{a.op} needs a service")
    out = {"expose": lambda: expose(a.service, a.org),
           "adopt": lambda: adopt(a.service, a.cve, a.org),
           "list": lambda: list_changes(a.org),
           "revert": lambda: revert(a.org)}[a.op]()
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
