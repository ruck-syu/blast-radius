# Blast Radius

Agent that triages software supply-chain vulnerabilities by reasoning over a
**FalkorDB** graph. Given a CVE ID it finds every affected service through
transitive dependencies, determines public reachability, ranks by
risk (severity × exposure × criticality), identifies owners, simulates fixes
in sandbox graph copies, and acts — every action backed by a verified graph
path as proof.

**Track 01, Agents That Act on Connected Data.** Full build spec is
`blast-radius-build-spec.md` (parent directory, not part of the submission).

```
Ingestion jobs -> FalkorDB <-> MCP server <-> Agent (LLM) -> Action tools
                      ^                            |
                      +---- Web UI (ranked list, paths, simulation, action log)
```

## Setup (fresh machine)

Prerequisites: Docker + Docker Compose, Python 3.10+.

```bash
git clone <this-repo> && cd blast-radius
cp .env.example .env            # optional: add LLM / GitHub / Slack keys (see below)
docker compose up -d            # FalkorDB on localhost:6379
pip install -r requirements.txt
python -m ingest.generate --all # two synthetic orgs, canonical seeds (dev 42, held-out 1337)
python -m ingest.load --all     # ~22k nodes / ~39k edges per graph
python -m ingest.verify --org dev && python -m ingest.verify --org heldout
```

Verify each phase (all must print ALL PASS / ACCEPTANCE PASS), or run them
all with `python check.py` (one PASS/FAIL line per suite, failing output shown):

```bash
python -m mcp_server.test_tools      # Phase 2: read tools vs ground truth
python -m agent.test_agent           # Phase 3: end-to-end triage
python -m agent.test_simulation      # Phase 4: fix comparison
python -m agent.test_actions         # Phase 5: guardrail accept/refuse, sandbox-checked fix PRs
python -m mcp_server.test_apply      # incremental updates + revert
python -m agent.test_mcp_agent       # MCP agent: tool discovery, trace, verdict/proof checks (scripted LLM, no key)
python -m agent.test_gate            # pre-merge gate: sandbox assess, transitive pulls, upgrades, SBOM diff, live graph untouched
python -m ui.test_ui                 # UI API: triage, SSE investigate, approve, refusal drill, live change
python -m benchmark.runner --org all # Phase 7: 3 systems, held-out numbers
python -m ui.server                  # Phase 6: http://127.0.0.1:8765
```

Tests that act write to a temp action log and delete the Decision nodes they
create. `python -m agent.reset_demo` clears all Decision nodes, live changes
and the action log before a demo recording.

Live deployment: point the env at FalkorDB Cloud or any self-hosted instance
(`FALKORDB_HOST/PORT/USERNAME/PASSWORD` in `.env`) — no code changes needed;
`docker compose` is just the default local backend. Optional live wires:
`LLM_PROVIDER` + `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` (summary wording),
`GITHUB_TOKEN` + `DEMO_REPO` (real tickets on our own demo repo),
`SLACK_WEBHOOK` (real notifications). Without them the product runs fully in
dry-run/template mode with the guardrail enforced. `.env` is read at startup
(real environment variables win), so keys put there reach every entry point.

## Usage

```bash
python -m agent.triage CVE-2021-44228 [--org heldout] [--json] [--compare-fixes]
python -m agent.act CVE-2021-44228 [--verdicts ACT_NOW] [--pr]
python -m agent.mcp_agent CVE-2021-44228 [--org heldout] [--allow-actions]  # Claude picks tools over MCP
python -m agent.mcp_agent CVE-2021-44228 --offline     # no key: fixed tool sequence, same MCP loop and checks
python -m agent.mcp_agent --question "Is d-checkout-api exposed to CVE-2021-44228, and how does public traffic reach it?"
python -m agent.live expose d-notify-svc | adopt d-search-api --cve CVE-2021-44228 | list | revert
python -m mcp_server.server   # MCP stdio transport for external clients
```

`agent.mcp_agent` is an MCP client: it spawns the server over stdio, discovers
the tools with `list_tools`, and Claude chooses each next call from what the
graph returned so far, giving a one-line reason per call (printed as the trace).
Verdicts it submits are re-derived from the `evaluate_rules` output it saw, and
each service's proof path is verified edge by edge; disagreements are flagged.
Needs `ANTHROPIC_API_KEY` (model `LLM_MODEL`, default `claude-opus-5-5`).
`--offline` swaps Claude for `agent/offline_planner.py`, a fixed policy (not a
model): get_cve, score_risk, evaluate_rules per service, find_owner for ACT_NOW,
rank_criticality, then verdicts from the rules. It goes through the same MCP
client and checks, so the loop runs without a key and gives a baseline to
compare Claude's tool choices against.

Every reachable service also gets an **exposure proof**: the shortest public
route (`Endpoint -ROUTES_TO-> Service -CALLS->* Service`), verified edge by
edge like the dependency proof, with the start checked to be a public endpoint.
Together the two proofs are the full attack chain: internet → service →
vulnerable package → CVE.

### Web UI

`python -m ui.server`, then http://127.0.0.1:8765:

- **Blast map**: layered graph of public endpoints → affected services →
  dependency chain → vulnerable package → CVE. Hover a service to trace its
  paths, click to inspect.
- **Ranked services** + **Why**: verdict, risk, rules, owner, and the attack
  chain with both proofs marked verified.
- **Investigate with Claude**: streams the MCP agent's trace live (tool, reason,
  digest of what came back) over Server-Sent Events, then a findings table
  showing whether each verdict agrees with the rules and the proof verified.
  *Approve* acts only on ACT_NOW findings that pass both checks: a human in
  the loop on top of the guardrail. Disabled with a note when no key is set;
  *Offline planner (no model)* runs the same MCP loop, trace and checks with
  a fixed tool sequence instead, labelled as such.
- **Live change**: expose a service to the internet or make a service adopt
  the vulnerable package. *Check in sandbox* predicts the outcome the way the
  pre-merge gate does; *Apply* changes the live graph through `apply_change`,
  re-triages and shows what flipped (e.g. SCHEDULE → ACT_NOW with the new
  route verified). Revert removes exactly those changes (provenance-tagged).
- **Fix simulation**, **Actions** (ticket + notify, guardrail drill with a
  forged proof), **Decisions** recorded in the graph, and the **Action log**.

API (documented in the `ui/server.py` docstring): `GET /api/triage`,
`/api/compare`, `/api/cves`, `/api/config`, `/api/decisions`,
`/api/action_log`, `/api/services`, `/api/live`, `/api/investigate` (SSE);
`POST /api/act`, `/api/refusal_drill`, `/api/live`, `/api/live_revert`,
`/api/assess`.

Tools (all parameterized Cypher from `queries/`, see below):
`get_cve`, `find_affected_services`, `check_reachability`, `dependency_path`,
`rank_criticality`, `find_owner`, `score_risk`, `evaluate_rules`,
`simulate_fix`, `assess_change`, `apply_change`, `create_ticket`, `notify_owner`,
`open_fix_pr`.

Every action tool refuses without a proof path whose every edge exists in the
graph. `open_fix_pr` adds a second check: the upgrade is applied to a sandbox
copy first, and the PR is refused unless it resolves that CVE for that service
without opening new ACT_NOW exposure (pinning `xz@5.6.1` as a "fix" for log4j is
refused with CVE-2024-3094 named). The sandbox result goes in the PR body.

## Where it fits in the workflow

| When | Entry point | What happens |
|------|-------------|--------------|
| A PR changes dependencies or routes | `python -m agent.gate` in CI (base vs PR CycloneDX SBOMs, or explicit purls) | the change is applied to a sandbox copy of the graph, every CVE re-scored; exit 1 with a markdown PR comment if it opens new ACT_NOW exposure (transitive pulls included); upgrades are credited with what they resolve |
| A new CVE lands | `python -m agent.triage` / `agent.mcp_agent` / the UI | blast radius, public routes, verdicts, owners, each with a verified proof |
| Verdicts are in | `python -m agent.act`, or Approve in the UI | tickets + owner notifications, refused without a verified proof |
| Choosing what to fix first | Simulate fixes / `simulate_fix` | each upgrade re-scored in a sandbox copy; biggest org-wide risk drop wins |
| Ad-hoc questions | Claude Code (`.mcp.json` in this repo) or any MCP client | the same graph tools, the model picks which to call |

Pre-merge gate, for a PR that makes `d-billing-worker` depend on a package
that pulls log4j-core 2.14.1 in two hops down:

```bash
python -m agent.gate --service d-billing-worker --adds pkg:npm/syn-d-pkg-03519@1.19.5
# ## Blast Radius pre-merge check: FAIL: new ACT_NOW exposure
# | CVE-2021-44228 | d-billing-worker | not affected → ACT_NOW | public via /api/d/v1/route-02; ... |
# exit 1
```

In CI, point `FALKORDB_HOST`/`PORT`/`USERNAME`/`PASSWORD` at the org's graph and
diff the SBOMs of the base branch and the PR branch (syft/cdxgen output, any
CycloneDX JSON):

```bash
python -m agent.gate --sbom-before base.cdx.json --sbom-after pr.cdx.json
```

The service comes from `metadata.component.name`. Components only in the PR
SBOM are adds (new direct dependencies first, so the rest of a flattened
subtree is recognised as pulled in and the report keeps the real transitive
chain); components only in the base SBOM are removes: the service no longer
resolves them, so a (CVE, service) pair survives only if some dependency path
avoids every removed version. An upgrade PR therefore passes with
"resolves N" and lists what it fixes:

```bash
python -m agent.sbom d-recommend-api > base.cdx.json     # stand-in for syft, from the graph
python -m agent.sbom d-recommend-api \
  --drop pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 \
  --add  pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1 > pr.cdx.json
python -m agent.gate --sbom-before base.cdx.json --sbom-after pr.cdx.json
# ## Blast Radius pre-merge check: PASS: no new exposure, resolves 1
# - CVE-2021-44228 on `d-recommend-api`: was ACT_NOW, no longer affected
```

Explicit `--adds`/`--removes PURL...` work too; `--expose PATH` for new public
routes, `--fail-on SCHEDULE` to be stricter, `--json` for tooling. The live
graph is never written; each run uses its own sandbox and deletes it.
[`examples/ci/blast-radius-gate.yml`](examples/ci/blast-radius-gate.yml) is a
GitHub Actions workflow for a service repo: syft SBOMs of base and PR, the
gate, a sticky PR comment with the report, and a failed check on new ACT_NOW.

Opening this repo in Claude Code offers the `blast-radius` MCP server from
`.mcp.json` (approve it once); other MCP clients run
`python -m mcp_server.server` from the repo root over stdio.

## Graph data model

```mermaid
graph LR
    CVE -- AFFECTS --> Package
    Package -- DEPENDS_ON --> Package
    Service -- USES --> Package
    Service -- CALLS --> Service
    Endpoint -- ROUTES_TO --> Service
    Service -- OWNED_BY --> Team
    Person -- MEMBER_OF --> Team
    Person -- DEPLOYED --> Deployment
    Deployment -- OF --> Service
    CVE -- FIXED_IN --> Package
    Package -- SUPERSEDED_BY --> Package
    Decision -- ABOUT --> CVE
    Decision -- ABOUT --> Service
    Decision -- FIRED --> Rule
```

| Node | Key properties |
|------|---------------|
| `CVE` | `id`, `cvss`, `epss`, `in_kev`, `summary`, `published` |
| `Package` | `name`, `version`, `ecosystem`, `purl` |
| `Service` | `name`, `tier` (critical/standard/internal), `repo`, `language` |
| `Endpoint` | `path`, `public` |
| `Team` | `name`, `slack_channel` |
| `Person` | `name`, `handle` |
| `Deployment` | `id`, `timestamp`, `version` |
| `Rule` | `id` (`R_KEV`, `R_PUBLIC_REACH`, `R_CRITICAL_TIER`, `R_NO_REACH`, `R_FIX_AVAILABLE`), `weight` |
| `Decision` | `id`, `timestamp`, verdict (`ACT_NOW`/`SCHEDULE`/`SUPPRESS`), `rationale`, `proof_path` (node-id list) |

Indexes on `CVE.id`, `Package.purl`, `Service.name`. Full definitions plus scale
record (22,234 nodes / 39,096 edges dev; 22,240 / 39,214 held-out):
`docs/data-model.md`.

## Queries and graph algorithms

Every query the product depends on lives in [`queries/`](queries/) (one file
per traversal, one-line purpose comment each). Core traversals:
`find_affected_services`, `check_reachability`, `dependency_path`,
`score_risk` (risk formula in Cypher), `evaluate_rules` (named rules in
Cypher), `rank_criticality` (FalkorDB `algo.pageRank` + exact
`algo.betweenness` over the CALLS graph, procedure names verified live; triage
cites each affected service's rank), plus guardrail
(`verify_edge`, `verify_path_start`, `verify_path_cve_anchor`,
`write_decision`), simulation (`upgrade_path`, `upgrade_uses`,
`upgrade_depends`, `remove_fixed_affects`), incremental updates (`apply_*`,
`list_live_changes`, `revert_live_*`), pre-merge checks (`package_exists`, `service_resolves`,
`dependency_path_avoiding`, `service_sbom`),
and UI helpers (`get_cve`, `list_cves`, `list_services`, `list_decisions`,
`call_graph_edges`).
Depth bounds are literals injected after int validation — FalkorDB
variable-length bounds cannot be query parameters, and the agent never writes
free-form Cypher against the live graph.

## Why the graph is essential

Held-out benchmark (27 questions: 1-hop / 2–3-hop / 4–6-hop / counterfactual):

| system | overall | 4–6-hop | path validity |
|--------|---------|---------|---------------|
| agent (parameterized tools, depth-bounded) | **0.998** | 1.000 | **1.000** |
| unbounded-Cypher proxy | 0.632 | 0.579 | never cites |
| flat lexical tables | 0.293 | **0.000** | never cites |
| agent, graph removed (ablation) | **0.000** | 0.000 | — |

Flat retrieval answers single lookups but is blind past one hop; unconstrained
Cypher degrades with hop count and cites no verifiable paths; removing
FalkorDB kills every capability (27/27 errors). Full table, metrics
(P/R, P@k/MRR, latency), and methodology: [`benchmark/results/SUMMARY.md`](benchmark/results/SUMMARY.md),
[`benchmark/METHODOLOGY.md`](benchmark/METHODOLOGY.md).

## Data statement

All data is public or synthetic. Public: CVE/advisory metadata (IDs, CVSS,
summaries) and real package names/versions for the three vulnerable/fixed
pairs. Synthetic (labelled `synthetic:true`, fictional people/teams):
services, endpoints, package dependency edges, teams, persons, deployments.
No private, login-protected, paywalled, or personal data. Two separate graphs
(`blast_radius_dev`, seed 42; `blast_radius_heldout`, seed 1337) so held-out
evaluation is genuinely unseen.

## Evaluation methodology

Ground truth is planted by the seeded generator (truly affected / truly
reachable / best fix per org) into `benchmark/ground_truth.json`.
`benchmark/questions.py` derives 27 questions/org; `benchmark/runner.py`
scores three systems on identical questions (scalar accuracy, set P/R,
ranked P@k + MRR with reachability as relevance, endpoint accuracy + shared
edge-by-edge path validity). Baselines are documented no-LLM stand-ins
(lexical SQLite; unbounded-Cypher templates) with a real LLM-writer hook
(`--writer llm`) for keyed runs. No tuning on either org — thresholds predate
the benchmark; CVE IDs overlap dev/held-out by construction while the
held-out graph is unseen. Small benchmark → modest claims only.

## AI-usage disclosure

See [`AI_USAGE.md`](AI_USAGE.md) (every AI tool used and for what, updated per phase).

## Deliverables status

- [x] Public source repository (this repo — push to publish)
- [x] Live deployment **or** complete local setup (local compose + FalkorDB Cloud env support; see Setup)
- [ ] Demo video — record with [`docs/demo-script.md`](docs/demo-script.md) (7 steps, ~6 min)

## Related work

- FalkorDB `GRAPH.COPY` semantics (server-side clone incl. indexes; dest must
  not exist; source stays readable) — verified against the
  [official docs](https://docs.falkordb.com/commands/graph.copy) and
  empirically (89 ms full clone of the 22k-node graph). Basis of `simulate_fix`.
- FalkorDB command/Cypher reference (Redis-protocol `GRAPH.QUERY`,
  OpenCypher subset, no Bolt) — from the
  [official docs](https://docs.falkordb.com/commands); basis for the
  queries-per-file rule and the no-guessed-procedures policy.
