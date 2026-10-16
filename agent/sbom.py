"""Export a service's resolved dependency tree from the graph as a CycloneDX SBOM.

Stands in for syft/cdxgen in the demo: the gate diffs two of these (base branch
vs PR branch). Direct dependencies are listed under the root in `dependencies`.

  python -m agent.sbom d-recommend-api > base.cdx.json
  python -m agent.sbom d-recommend-api --drop <purl> --add <purl> > pr.cdx.json
"""
from __future__ import annotations

import argparse
import json

from mcp_server import graph
from ingest.config import graph_name


def export(service: str, org: str = "dev", add: list[str] | None = None,
           drop: list[str] | None = None) -> dict:
    rows, _ = graph.run_on(graph_name(org), "service_sbom", {"service": service})
    if not rows:
        raise ValueError(f"no dependencies for service {service!r} in the {org} graph")
    comps = {r[0]: {"type": "library", "name": r[1], "version": r[2], "purl": r[0],
                    "bom-ref": r[0]} for r in rows}
    direct = {r[0] for r in rows if r[3]}
    for p in drop or []:
        comps.pop(p, None)
        direct.discard(p)
    for p in add or []:
        name, _, version = p.rpartition("/")[2].partition("@")
        comps[p] = {"type": "library", "name": name, "version": version, "purl": p,
                    "bom-ref": p}
        direct.add(p)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": service,
                                       "bom-ref": service}},
            "components": [comps[k] for k in sorted(comps)],
            "dependencies": [{"ref": service, "dependsOn": sorted(direct)}]}


def main() -> None:
    ap = argparse.ArgumentParser(description="CycloneDX SBOM for a service, from the graph")
    ap.add_argument("service")
    ap.add_argument("--org", default="dev")
    ap.add_argument("--add", nargs="*", default=[], metavar="PURL",
                    help="simulate a PR: add these components")
    ap.add_argument("--drop", nargs="*", default=[], metavar="PURL",
                    help="simulate a PR: drop these components")
    a = ap.parse_args()
    print(json.dumps(export(a.service, a.org, a.add, a.drop), indent=2))


if __name__ == "__main__":
    main()
