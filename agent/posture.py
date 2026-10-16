"""Org posture across every CVE in the graph: which services carry the most
urgent exposure, and which package upgrade clears the most (and whether the
upgrade target is itself affected).

  python -m agent.posture [--org heldout] [--limit 10] [--json]
"""
from __future__ import annotations

import argparse
import json

from mcp_server.posture import org_posture


def _n(k: int, word: str) -> str:
    return f"{k} {word}" + ("" if k == 1 else "s")


def report(r: dict) -> str:
    out = [f"{r['org']}: {r['cves']} CVEs, {r['pairs']} (CVE, service) pairs, "
           f"{r['act_now_pairs']} ACT_NOW across {r['services_affected']} services "
           f"({r['latency_ms']:.0f} ms)", "", "Packages (fix these first):"]
    for p in r["packages"]:
        carried = p["target_affected_by"]
        kev = sum(c["in_kev"] for c in carried)
        target = (f"upgrade to {p['upgrade_to']}" if p["upgrade_to"] else "no upgrade in graph")
        if carried:
            target += (f", which is itself affected by {_n(len(carried), 'CVE')}"
                       + (f" ({kev} KEV)" if kev else ""))
        out.append(f"  {p['purl']}: {_n(len(p['cves']), 'CVE')}, "
                   f"{_n(p['act_now_pairs'], 'ACT_NOW pair')} on {_n(p['services'], 'service')}; {target}")
    out += ["", "Services:"]
    for s in r["services"]:
        act = [c["cve"] for c in s["cves"] if c["verdict"] == "ACT_NOW"]
        out.append(f"  {s['service']}: {s['ACT_NOW']} ACT_NOW, {s['SCHEDULE']} SCHEDULE, "
                   f"{s['SUPPRESS']} SUPPRESS, risk {s['risk']}"
                   + (f" [{', '.join(act[:6])}{', ...' if len(act) > 6 else ''}]" if act else ""))
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--org", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    r = org_posture(args.org, args.limit)
    print(json.dumps(r, indent=2) if args.json else report(r))


if __name__ == "__main__":
    main()
