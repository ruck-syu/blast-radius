"""Synthetic org generator (seeded, reproducible).

Plants ground truth: which services are truly affected, truly reachable,
and which fix is best. Writes:
  ingest/seed_<org>.json        full graph to load into FalkorDB
  benchmark/ground_truth.json   planted answers for evaluation

Usage:
  python -m ingest.generate --org dev --seed 42
  python -m ingest.generate --org heldout --seed 1337
  (or --all to generate both with canonical seeds)

All people/teams are fictional and labelled synthetic:true.
CVE metadata (ids, scores) is public advisory data.
Package dependency edges are synthetic but shaped like real lockfiles.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict, deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# Public CVE metadata (scores/summaries are public advisory data).
CVES = [
    {
        "id": "CVE-2021-44228",
        "cvss": 10.0,
        "epss": 0.97,
        "in_kev": True,
        "summary": "Apache Log4j2 JNDI features allow RCE via crafted log message.",
        "published": "2021-12-10",
        "vuln_pkg": {"name": "log4j-core", "version": "2.14.1",
                     "ecosystem": "maven", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        "fixed_pkg": {"name": "log4j-core", "version": "2.17.1",
                      "ecosystem": "maven", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"},
        "range": "<2.15.0",
    },
    {
        "id": "CVE-2024-3094",
        "cvss": 10.0,
        "epss": 0.52,
        "in_kev": True,
        "summary": "XZ Utils backdoor in 5.6.0/5.6.1 allows RCE via sshd.",
        "published": "2024-03-29",
        "vuln_pkg": {"name": "xz", "version": "5.6.1",
                     "ecosystem": "conan", "purl": "pkg:conan/xz@5.6.1"},
        "fixed_pkg": {"name": "xz", "version": "5.6.2",
                      "ecosystem": "conan", "purl": "pkg:conan/xz@5.6.2"},
        "range": "=5.6.0||=5.6.1",
    },
    {
        "id": "CVE-2017-5638",
        "cvss": 10.0,
        "epss": 0.91,
        "in_kev": True,
        "summary": "Apache Struts2 Jakarta Multipart parser RCE via Content-Type.",
        "published": "2017-03-07",
        "vuln_pkg": {"name": "struts2-core", "version": "2.3.31",
                     "ecosystem": "maven", "purl": "pkg:maven/org.apache.struts/struts2-core@2.3.31"},
        "fixed_pkg": {"name": "struts2-core", "version": "2.5.10.1",
                      "ecosystem": "maven", "purl": "pkg:maven/org.apache.struts/struts2-core@2.5.10.1"},
        "range": "<2.5.10.1",
    },
]

TEAMS = ["Nebula", "Quasar", "Halide", "Vantage", "Cobalt", "Driftline"]
PERSONS = [
    ("Ada Lark", "@adalark"), ("Bram Ives", "@bramives"), ("Cleo Marsh", "@cleomarsh"),
    ("Dario Venn", "@dariovenn"), ("Elif Sorrel", "@elifsorrel"), ("Finn Calder", "@finncalder"),
    ("Greta Moss", "@gretamoss"), ("Hugo Reyes", "@hugoreyes"), ("Iris Bell", "@irisbell"),
    ("Jasper Quinn", "@jasperquinn"), ("Kira Novak", "@kiranovak"), ("Liam Okafor", "@liamokafor"),
    ("Mira Patel", "@mirapatel"), ("Nico Frost", "@nicofrost"), ("Opal June", "@opaljune"),
    ("Petra Lind", "@petralind"), ("Quinn Ash", "@quinnash"), ("Rosa Diaz", "@rosadiaz"),
]
SERVICE_BASE = [
    "checkout-api", "billing-worker", "auth-gateway", "search-api", "notify-svc",
    "ledger-api", "risk-engine", "feed-indexer", "media-proxy", "session-store",
    "pricing-api", "shipping-svc", "invoice-gen", "audit-trail", "feature-flags",
    "user-profile", "recommend-api", "cache-warmer", "webhook-relay", "data-export",
]
LANGUAGES = ["python", "typescript", "go"]
TIERS = ["critical", "standard", "internal"]

RULES = [
    {"id": "R_KEV", "description": "CVE is in the known-exploited list, boost.", "weight": 2.0},
    {"id": "R_PUBLIC_REACH", "description": "Service reachable from a public endpoint within depth bound, boost.", "weight": 2.5},
    {"id": "R_CRITICAL_TIER", "description": "Service tier is critical or has high PageRank, boost.", "weight": 1.5},
    {"id": "R_NO_REACH", "description": "Vulnerable package present but no path from any public endpoint, reduce.", "weight": -1.5},
    {"id": "R_FIX_AVAILABLE", "description": "A FIXED_IN version exists, mark as actionable.", "weight": 0.5},
]

CANONICAL_SEEDS = {"dev": 42, "heldout": 1337}
N_PACKAGES = 22000
N_SERVICES = 60


def gen_org(org: str, seed: int, n_packages: int = N_PACKAGES) -> dict:
    rng = random.Random(seed)
    prefix = "d" if org == "dev" else "h"

    packages: list[dict] = []  # synthetic transitive packages
    depends_on: list[tuple[int, int]] = []  # (child_idx, parent_idx) over packages+vuln nodes

    # Vuln + fixed packages come first (indices into a combined pkg list).
    vuln_pkgs = [dict(c["vuln_pkg"]) for c in CVES]
    fixed_pkgs = [dict(c["fixed_pkg"]) for c in CVES]
    # combined index space: 0..2 vuln, 3..5 fixed, 6.. synthetic
    V = len(vuln_pkgs)
    n_syn = n_packages
    half = n_syn // 2

    for i in range(n_syn):
        packages.append({
            "name": f"syn-{prefix}-pkg-{i:05d}",
            "version": f"1.{i % 20}.{i % 7}",
            "ecosystem": "npm",
            "purl": f"pkg:npm/syn-{prefix}-pkg-{i:05d}@1.{i % 20}.{i % 7}",
            "synthetic": True,
        })

    def gidx_syn(i: int) -> int:
        return 2 * V + i  # offset past vuln+fixed

    # Vuln-reachable half: split into 3 thirds, each rooted on ONE vuln package,
    # so each CVE has a distinct blast radius (meaningful best-fix comparison).
    # Deps stay within the same third (+ direct edge to its own vuln).
    third = half // 3
    for i in range(half):
        group = min(i // third, 2)  # which CVE this package belongs to
        base = group * third
        n_deps = rng.choice([1, 1, 2, 2, 3])
        for _ in range(n_deps):
            if i - base < 40 or rng.random() < 0.08:
                parent = group  # direct edge to own vuln package
            else:
                parent = gidx_syn(base + rng.randrange(i - base))  # earlier in same third
            depends_on.append((gidx_syn(i), parent))
    # Clean half: only depend within clean half (never reaches vuln).
    for i in range(half, n_syn):
        n_deps = rng.choice([1, 1, 2, 2, 3])
        for _ in range(n_deps):
            if i == half or rng.random() < 0.05:
                # root of clean subgraph: no deps (skip)
                continue
            parent = gidx_syn(half + rng.randrange(i - half))
            depends_on.append((gidx_syn(i), parent))

    # Services: ~1/3 per CVE group use that third's packages (affected by that
    # CVE only), plus a clean group (unaffected). s % 4 == 3 -> clean.
    services = []
    uses: list[tuple[int, int]] = []  # (service_idx, gidx)
    third = half // 3
    for s in range(N_SERVICES):
        base = SERVICE_BASE[s % len(SERVICE_BASE)]
        suffix = f"-{s // len(SERVICE_BASE) + 1}" if s >= len(SERVICE_BASE) else ""
        tier = rng.choice(TIERS[:2]) if s < 12 else rng.choice(TIERS)
        services.append({
            "name": f"{prefix}-{base}{suffix}",
            "tier": tier,
            "repo": f"github.com/demo-org/{prefix}-{base}{suffix}",
            "language": rng.choice(LANGUAGES),
            "synthetic": True,
        })
        group = s % 4  # 0,1,2 -> CVE groups; 3 -> clean
        for _ in range(rng.choice([2, 3, 3])):
            if group == 3:
                pkg = gidx_syn(half + rng.randrange(n_syn - half))  # clean -> unaffected
            else:
                pkg = gidx_syn(group * third + rng.randrange(third))
            uses.append((s, pkg))

    # CALLS DAG: each service calls 0-3 lower-index services.
    calls: list[tuple[int, int]] = []
    for s in range(N_SERVICES):
        if s == 0:
            continue
        for _ in range(rng.choice([0, 1, 1, 2])):
            calls.append((s, rng.randrange(s)))

    # Endpoints route to random services; ~half public.
    endpoints = []
    for e in range(24):
        endpoints.append({
            "path": f"/api/{prefix}/v1/route-{e:02d}",
            "public": e % 2 == 0,
            "to": rng.randrange(N_SERVICES),
            "synthetic": True,
        })

    teams = [{"name": f"Team {t} ({org})", "slack_channel": f"#{t.lower()}-{prefix}",
              "synthetic": True} for t in TEAMS]
    persons = [{"name": n, "handle": h, "team": rng.randrange(len(teams)),
                "synthetic": True} for n, h in PERSONS]
    deployments = []
    ts = 1_700_000_000
    for s in range(N_SERVICES):
        for k in range(rng.choice([1, 2, 2, 3])):
            deployments.append({
                "id": f"{prefix}-dep-{s:03d}-{k}",
                "timestamp": ts + s * 10000 + k * 1000,
                "version": f"v2.{s}.{k}",
                "service": s,
                "by": rng.randrange(len(persons)),
                "synthetic": True,
            })

    # ---- ground truth via BFS on the generated graph ----
    # adjacency child -> parents (depends direction)
    parents: dict[int, list[int]] = defaultdict(list)
    for c, p in depends_on:
        parents[c].append(p)
    # vuln gidx set
    vuln_of_cve: dict[str, int] = {c["id"]: i for i, c in enumerate(CVES)}  # gidx = vuln index
    # pkg_of_service roots
    svc_roots: dict[int, list[int]] = defaultdict(list)
    for s, g in uses:
        svc_roots[s].append(g)

    def shortest_to_vuln(roots: list[int]) -> dict[str, int]:
        """BFS from roots following parents; return {cve_id: depth} (edges)."""
        dist: dict[int, int] = {}
        q = deque()
        for r in roots:
            if r not in dist:
                dist[r] = 0
                q.append(r)
        found: dict[str, int] = {}
        while q:
            n = q.popleft()
            for cve_id, vg in vuln_of_cve.items():
                if n == vg and cve_id not in found:
                    found[cve_id] = dist[n]
            for p in parents.get(n, []):
                if p not in dist:
                    dist[p] = dist[n] + 1
                    q.append(p)
        return found

    # CALLS reachability: entry services (public endpoints) can reach via CALLS*.
    # calls edges are (caller, callee); reachability flows entry -> ... via calls.
    call_adj: dict[int, list[int]] = defaultdict(list)
    for caller, callee in calls:
        call_adj[caller].append(callee)
    entry_services = {e["to"] for e in endpoints if e["public"]}

    def reachable_from_public(target: int) -> list[str]:
        """Entry points that can reach target via CALLS* (BFS from each entry)."""
        hits = []
        for entry in entry_services:
            seen = {entry}
            q = deque([entry])
            while q:
                n = q.popleft()
                if n == target:
                    hits.append(entry)
                    break
                for m in call_adj.get(n, []):
                    if m not in seen:
                        seen.add(m)
                        q.append(m)
        return [services[e]["name"] for e in hits]

    gt_cves = {}
    for cve in CVES:
        cve_id = cve["id"]
        affected, reachable = [], []
        for s in range(N_SERVICES):
            d = shortest_to_vuln(svc_roots[s])
            if cve_id in d:
                affected.append({"service": services[s]["name"], "depth": d[cve_id] + 1})
                entries = reachable_from_public(s)
                if entries:
                    reachable.append({"service": services[s]["name"],
                                      "depth": d[cve_id] + 1, "entries": entries})
        affected.sort(key=lambda x: (x["depth"], x["service"]))
        reachable.sort(key=lambda x: (x["depth"], x["service"]))
        gt_cves[cve_id] = {"affected": affected, "reachable": reachable}

    # best fix = CVE whose fix removes the most reachable services
    best_fix, best_n = None, -1
    for cve_id, info in gt_cves.items():
        n = len(info["reachable"])
        if n > best_n:
            best_fix, best_n = cve_id, n

    seed_doc = {
        "org": org, "seed": seed, "synthetic": True,
        "cves": CVES, "vuln_pkgs": vuln_pkgs, "fixed_pkgs": fixed_pkgs,
        "packages": packages, "depends_on": depends_on,
        "services": services, "uses": uses, "calls": calls,
        "endpoints": endpoints, "teams": teams, "persons": persons,
        "deployments": deployments, "rules": RULES,
    }
    truth = {
        "org": org, "seed": seed,
        "cves": gt_cves,
        "best_fix": {"cve": best_fix, "reachable_removed": best_n},
        "counts": {
            "packages": len(packages) + len(vuln_pkgs) + len(fixed_pkgs),
            "services": len(services),
        },
    }
    return seed_doc, truth


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", choices=["dev", "heldout"])
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--all", action="store_true", help="generate both orgs with canonical seeds")
    ap.add_argument("--n-packages", type=int, default=N_PACKAGES)
    args = ap.parse_args()

    orgs = ["dev", "heldout"] if args.all else [args.org or "dev"]
    combined_path = ROOT / "benchmark" / "ground_truth.json"
    combined = json.loads(combined_path.read_text()) if combined_path.exists() else {}

    for org in orgs:
        seed = args.seed if args.seed is not None and not args.all else CANONICAL_SEEDS[org]
        seed_doc, truth = gen_org(org, seed, args.n_packages)
        (HERE / f"seed_{org}.json").write_text(json.dumps(seed_doc))
        combined[org] = truth
        n_aff = {c: len(t["affected"]) for c, t in truth["cves"].items()}
        n_reach = {c: len(t["reachable"]) for c, t in truth["cves"].items()}
        print(f"{org}: seed={seed} pkgs={truth['counts']['packages']} "
              f"affected={n_aff} reachable={n_reach} best_fix={truth['best_fix']}")

    combined_path.parent.mkdir(parents=True, exist_ok=True)
    combined_path.write_text(json.dumps(combined, indent=2))
    print(f"wrote {combined_path}")


if __name__ == "__main__":
    main()
