"""Import real advisories from OSV.dev into the graph, so triage runs on a CVE the
moment it is published rather than only on seeded ones.

For each affected package in the advisory, every version of it in the graph is
checked against the advisory's ranges/versions; the affected ones get AFFECTS
edges and the lowest unaffected newer version in the graph becomes the fix
(FIXED_IN + SUPERSEDED_BY). CVSS comes from the CVSS v3 vector, KEV from the
CISA catalog, EPSS from FIRST. Imports are tagged source 'osv' and removable;
seeded CVEs are never overwritten.

  python -m ingest.osv CVE-2021-44832 [--org dev] [--dry-run]   # one advisory (CVE or GHSA id)
  python -m ingest.osv --file advisory.json [--kev no]           # OSV JSON on disk, no network for OSV
  python -m ingest.osv --scan [--org dev] [--dry-run]            # every advisory for the graph's real packages
  python -m ingest.osv --remove CVE-2021-44832 | --remove-all
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import urllib.request

from mcp_server import graph

OSV = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="

PURL_TYPE = {"Maven": "maven", "PyPI": "pypi", "npm": "npm", "Go": "golang",
             "crates.io": "cargo", "RubyGems": "gem", "NuGet": "nuget",
             "Packagist": "composer", "ConanCenter": "conan", "Hex": "hex", "Pub": "pub"}
# GHSA label -> lower bound of the CVSS band; used only when no v3 vector exists.
LABEL_CVSS = {"CRITICAL": 9.0, "HIGH": 7.0, "MODERATE": 4.0, "MEDIUM": 4.0, "LOW": 0.1}


def _fetch(url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "blast-radius/1.0", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def cvss3_base(vector: str) -> float | None:
    """CVSS v3.0/3.1 base score from a vector string (FIRST spec, section 7)."""
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope = m["S"]
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
        ac = {"L": .77, "H": .44}[m["AC"]]
        pr = {"N": .85, "L": .68 if scope == "C" else .62, "H": .5 if scope == "C" else .27}[m["PR"]]
        ui = {"N": .85, "R": .62}[m["UI"]]
        c, i, a = ({"H": .56, "L": .22, "N": 0}[m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
    if impact <= 0:
        return 0.0
    raw = impact + 8.22 * av * ac * pr * ui
    raw = min(raw if scope == "U" else 1.08 * raw, 10)
    n = round(raw * 100000)
    return n / 100000 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10


def vkey(v: str) -> tuple:
    """Sort key: numeric parts compare as numbers, qualifiers (beta, rc) sort
    before the release they qualify, so 2.0-beta7 < 2.0 < 2.0.1."""
    parts = [(2, int(t), "") if t.isdigit() else (0, 0, t.lower())
             for t in re.findall(r"\d+|[A-Za-z]+", v)]
    return tuple(parts) + ((1, 0, ""),)


def affects(version: str, entry: dict) -> bool:
    if version in entry.get("versions", []):
        return True
    k = vkey(version)
    for r in entry.get("ranges", []):
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        lo = None
        for e in r.get("events", []):
            if "introduced" in e:
                lo = () if e["introduced"] == "0" else vkey(e["introduced"])
            elif lo is not None and "fixed" in e:
                if lo <= k < vkey(e["fixed"]):
                    return True
                lo = None
            elif lo is not None and "last_affected" in e:
                if lo <= k <= vkey(e["last_affected"]):
                    return True
                lo = None
        if lo is not None and k >= lo:
            return True
    return False


def _range_text(entry: dict) -> str:
    out = []
    for r in entry.get("ranges", []):
        lo = None
        for e in r.get("events", []):
            if "introduced" in e:
                lo = e["introduced"]
            elif "fixed" in e or "last_affected" in e:
                hi = f"<{e['fixed']}" if "fixed" in e else f"<={e['last_affected']}"
                out.append(f">={lo} {hi}" if lo not in (None, "0") else hi)
                lo = None
        if lo is not None:
            out.append(f">={lo}")
    return ", ".join(out) or "listed versions"


def base_purl(pkg: dict) -> str | None:
    if pkg.get("purl"):
        return pkg["purl"].split("@")[0].split("?")[0]
    kind, name = PURL_TYPE.get(pkg.get("ecosystem", "")), pkg.get("name", "")
    if not kind or not name:
        return None
    if kind == "maven":
        name = name.replace(":", "/")
    elif kind == "pypi":
        name = name.lower().replace("_", "-")
    elif kind == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:{kind}/{name}"


def fetch_record(vuln_id: str) -> dict:
    """The OSV record, with package-level `affected` entries pulled from an alias
    (e.g. the GHSA) when the record itself only has CPE ranges (NVD CVE records)."""
    rec = _fetch(f"{OSV}/vulns/{vuln_id}")
    if not any(base_purl(a.get("package", {})) for a in rec.get("affected", [])):
        for alias in rec.get("aliases", []):
            try:
                other = _fetch(f"{OSV}/vulns/{alias}")
            except OSError:
                continue
            if any(base_purl(a.get("package", {})) for a in other.get("affected", [])):
                rec = {**other, "aliases": sorted({*other.get("aliases", []), rec["id"]} - {other["id"]}),
                       "severity": rec.get("severity") or other.get("severity")}
                break
    return rec


_kev_ids: set[str] | None = None


def _kev(cve: str) -> bool | None:
    global _kev_ids
    if _kev_ids is None:
        try:
            _kev_ids = {v.get("cveID") for v in _fetch(KEV_URL).get("vulnerabilities", [])}
        except (OSError, ValueError):
            return None
    return cve in _kev_ids


def _epss(cve: str) -> float | None:
    try:
        data = _fetch(EPSS_URL + cve).get("data", [])
        return float(data[0]["epss"]) if data else 0.0
    except (OSError, ValueError, KeyError):
        return None


def plan(rec: dict, org: str = "dev", kev: str = "auto", epss: float | None = None) -> dict:
    """What importing `rec` would write, checked against the org's graph. No writes."""
    cve = rec["id"] if rec["id"].startswith("CVE-") else next(
        (a for a in rec.get("aliases", []) if a.startswith("CVE-")), rec["id"])
    notes, score = [], None
    for s in rec.get("severity", []):
        if s.get("type", "").startswith("CVSS_V3"):
            score = cvss3_base(s["score"])
            break
    if score is None:
        label = (rec.get("database_specific") or {}).get("severity", "").upper()
        score = LABEL_CVSS.get(label, 0.0)
        notes.append(f"no CVSS v3 vector; cvss {score} from severity label {label or 'none'}")
    in_kev = {"yes": True, "no": False}.get(kev)
    if in_kev is None:
        in_kev = _kev(cve)
        if in_kev is None:
            notes.append("CISA KEV catalog unreachable; in_kev false")
            in_kev = False
    if epss is None:
        epss = _epss(cve)
        if epss is None:
            notes.append("EPSS unreachable; epss 0")
            epss = 0.0

    affected, fixes, unmatched = [], [], []
    for entry in rec.get("affected", []):
        no_fix: list[str] = []
        base = base_purl(entry.get("package", {}))
        if not base:
            continue
        rows, _ = graph.run(org, "packages_by_purl_prefix", {"prefix": base + "@"})
        if not rows:
            unmatched.append(base)
            continue
        same = [e for e in rec["affected"] if base_purl(e.get("package", {})) == base]
        hit = [(p, v) for p, v in rows if affects(v, entry)]
        safe = sorted(((p, v) for p, v in rows if not any(affects(v, e) for e in same)),
                      key=lambda x: vkey(x[1]))
        for p, v in hit:
            if p in {a["purl"] for a in affected}:
                continue
            affected.append({"purl": p, "range": _range_text(entry)})
            fix = next((sp for sp, sv in safe if vkey(sv) > vkey(v)), None)
            if fix:
                fixes.append((p, fix))
            else:
                no_fix.append(p.split("@")[1])
        if no_fix:
            notes.append(f"no fixed version of {base} in the graph for {', '.join(no_fix)}")
    unmatched = sorted(set(unmatched) - {a["purl"].split("@")[0] for a in affected})
    return {"cve": cve, "osv_id": rec["id"], "org": org, "cvss": score, "epss": round(epss, 4),
            "in_kev": in_kev, "summary": (rec.get("summary") or rec.get("details", ""))[:300],
            "published": (rec.get("published") or "")[:10], "affects": affected,
            "fixes": fixes, "not_in_graph": unmatched, "notes": notes}


def write(p: dict) -> dict:
    """Apply a plan. Refuses to touch seeded CVEs; re-importing an OSV CVE updates it."""
    rows, _ = graph.run(p["org"], "cve_source", {"id": p["cve"]})
    if rows and rows[0][0] != "osv":
        return {**p, "imported": False, "reason": f"{p['cve']} is seeded data; not overwriting"}
    if not p["affects"]:
        return {**p, "imported": False, "reason": "no affected package version is in the graph"}
    graph.run(p["org"], "import_cve", {
        "id": p["cve"], "cvss": float(p["cvss"]), "epss": float(p["epss"]),
        "in_kev": bool(p["in_kev"]), "summary": p["summary"], "published": p["published"],
        "osv_id": p["osv_id"], "affects": p["affects"]})
    for old, new in p["fixes"]:
        graph.run(p["org"], "import_fix_link", {"cve": p["cve"], "old_purl": old, "new_purl": new})
    return {**p, "imported": True}


def remove(org: str, cve: str = "") -> dict:
    rows, _ = graph.run(org, "remove_imported_cve", {"id": cve})
    pruned, _ = graph.run(org, "prune_imported_upgrades", {})
    return {"org": org, "removed": rows[0][0], "upgrade_edges": pruned[0][0] if pruned else 0}


def scan_ids(org: str) -> list[str]:
    """OSV ids of every advisory affecting a real (non-synthetic) package in the graph."""
    purls = [r[0] for r in graph.run(org, "real_packages", {})[0]]
    res = _fetch(f"{OSV}/querybatch", {"queries": [{"package": {"purl": p}} for p in purls]})
    return sorted({v["id"] for r in res.get("results", []) for v in r.get("vulns", [])})


def describe(p: dict) -> str:
    head = (f"{p['cve']} ({p['osv_id']}) cvss {p['cvss']} epss {p['epss']} "
            f"kev {'yes' if p['in_kev'] else 'no'}")
    lines = [head] + [f"  affects {a['purl']} ({a['range']})" for a in p["affects"]]
    lines += [f"  fix     {old} -> {new}" for old, new in p["fixes"]]
    lines += [f"  note    {n}" for n in p["notes"]]
    if p.get("reason"):
        lines.append(f"  skipped: {p['reason']}")
    elif not p["affects"]:
        lines.append("  no affected version in the graph" + (
            f" (not in graph: {', '.join(p['not_in_graph'])})" if p["not_in_graph"]
            else " (the versions present are outside the affected ranges)"))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("ids", nargs="*", help="OSV ids (CVE-..., GHSA-...)")
    ap.add_argument("--org", default="dev", choices=["dev", "heldout"])
    ap.add_argument("--file", help="OSV JSON record on disk instead of fetching")
    ap.add_argument("--scan", action="store_true", help="import every advisory for the graph's real packages")
    ap.add_argument("--kev", default="auto", choices=["auto", "yes", "no"])
    ap.add_argument("--epss", type=float, help="EPSS override (skips the FIRST API)")
    ap.add_argument("--dry-run", action="store_true", help="show what would be written")
    ap.add_argument("--remove", metavar="CVE", help="delete one imported CVE")
    ap.add_argument("--remove-all", action="store_true", help="delete every imported CVE")
    args = ap.parse_args()

    if args.remove or args.remove_all:
        r = remove(args.org, args.remove or "")
        print(f"{args.org}: removed {r['removed']} imported CVEs, {r['upgrade_edges']} upgrade edges")
        return
    try:
        if args.file:
            with open(args.file) as f:
                records = [json.load(f)]
        else:
            ids = scan_ids(args.org) if args.scan else args.ids
            if not ids:
                ap.error("give an advisory id, --file or --scan")
            records = [fetch_record(i) for i in ids]
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)

    seen, imported = set(), []
    for rec in records:
        p = plan(rec, args.org, args.kev, args.epss)
        if p["cve"] in seen:
            continue
        seen.add(p["cve"])
        if not args.dry_run:
            p = write(p)
            imported += [p["cve"]] if p.get("imported") else []
        print(describe(p))
    if imported:
        print(f"\nimported {len(imported)} into {args.org}. Triage: python -m agent.triage {imported[0]}"
              + ("" if args.org == "dev" else f" --org {args.org}"))
    elif args.dry_run:
        print("\ndry run: nothing written")


if __name__ == "__main__":
    main()
