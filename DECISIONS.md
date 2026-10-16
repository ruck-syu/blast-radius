# DECISIONS.md

Non-obvious choices (choice, reason, rejected alternatives).

- Synthetic org generator uses seeded RNG so dev (`seed 42`) and held-out (`seed 1337`) orgs are reproducible. Rejected: unseeded random (breaks benchmark reproducibility).
- Scale target ~tens of thousands of nodes via fan-out of transitive package deps per service, not thousands of services (keeps org plausible while hitting node counts). Rejected: 10k services (unrealistic org, slow CALLS reasoning).
- Two graphs (`blast_radius_dev`, `blast_radius_heldout`) instead of one graph with org label, so held-out evaluation is a genuinely unseen graph. Rejected: single graph with filter (leakage risk).
- `FIXED_IN` / `SUPERSEDED_BY` edges are real version chains so `simulate_fix` follows an upgrade path. Rejected: arbitrary edge deletion.
- Depth bounds are literals in `.cypher` files, injected by `mcp_server/graph.py` after int validation (1..10), because FalkorDB variable-length bounds cannot be query parameters. Rejected: free-form Cypher from the agent (spec forbids it against the live graph).
- `find_affected_services` returns one row per service (shortest path via ordered `collect(path)[0]`, `min(depth)`), not one row per path — the dense DAG yields hundreds of paths per service otherwise. Rejected: path-per-row (breaks set precision/recall semantics).
- `rank_criticality` ranks by FalkorDB `algo.pageRank` + `algo.betweenness` over CALLS (procedure names verified live via `dbms.procedures()`), with degrees and the raw call edges as evidence. `score_risk` keeps its degree term so benchmark numbers stay comparable. Rejected: guessing a procedure name (spec forbids it).
- Pinned `mcp<2` (FastMCP API); v2 renamed FastMCP to MCPServer.
- Verdict thresholds (agent-side, from Cypher-fired rules): ACT_NOW = PUBLIC_REACH and (KEV or CRITICAL_TIER); SUPPRESS = NO_REACH and not KEV; else SCHEDULE. Rejected: LLM-decided verdicts (non-auditable).
- Agent calls the same tool functions the MCP server exposes (single implementation); stdio transport serves external clients. Rejected: separate agent/server tool copies (drift risk).
- LLM used only for summary wording, never for retrieval or verdicts; any LLM failure falls back to templates. Rejected: hard LLM dependency (breaks offline tests).
- Two agent modes. `agent.triage` is the deterministic, benchmarked plan. `agent.mcp_agent` is an MCP *client*: it discovers tools via `list_tools` over stdio and Claude picks each next call from prior results, giving a one-line `reason` per call (logged as the trace). Code keeps the authority: `apply_change` is never offered, action tools only with `--allow-actions` behind the proof guardrail, and each submitted verdict is re-derived from the `evaluate_rules` output the model saw, with proof paths attached from tool output and verified edge by edge. Rejected: LLM-only verdicts (non-auditable); having the model copy proof JSON into its answer (mangling risk, token cost).
- Default model `claude-opus-5-5` (override with `LLM_MODEL`); the MCP agent opts into server-side refusal fallbacks (`fallbacks: "default"`).
- Sandbox simulation uses server-side GRAPH.COPY (~90ms for 22k nodes, per FalkorDB docs) with try/finally deletion, not app-level rebuild. Rejected: replaying seed JSON (diverges from live graph once apply_change mutations exist).
- Fixes follow the real SUPERSEDED_BY/FIXED_IN upgrade path (rewire USES+DEPENDS_ON, drop resolved AFFECTS). Rejected: arbitrary edge removal (spec forbids it).
- Fix candidates are one upgrade per CVE in the org; recommendation maximizes org-wide risk reduction. Validated against planted best_fix on both orgs. Rejected: single-CVE-only candidates (disjoint blast radii make the comparison trivial).
- Actions default to dry-run (no tokens in this env); guardrail verification, Decision nodes, and the action log are always real. Rejected: live-by-default delivery (unsafe without a demo repo).
- Proof verification checks every asserted edge with id()+type() in FalkorDB plus service-start and CVE-anchor endpoints — a structurally valid but fabricated path cannot pass. Rejected: trusting agent-supplied paths.
- Decision nodes store proof_path as a node-id list per the data model; the full path object travels in tool payloads and the log.
- UI is stdlib Python + vanilla JS/SVG, no framework or build step (spec allows "any simple web UI"). Rejected: React + bundler (toolchain weight for a single-view console); hand-rolled SVG suffices for path chains.
- Benchmark baselines are documented no-LLM stand-ins (lexical SQLite; unbounded-Cypher templates) with a real LLM-writer hook for keyed runs. Rejected: fabricating LLM baseline numbers or skipping the 3-system comparison.
- Ranked benchmark relevance = reachability, not risk-score order, so the metric can't be gamed by reproducing our own scores. Rejected: ranking-against-own-output.
- No benchmark-driven tuning: post-run fixes were correctness bugs (or baseline improvements), thresholds untouched. Rejected: tuning rules/prompts on dev scores.
- `apply_change` upserts require referenced nodes to exist (validated, else error) instead of MERGE-creating unknowns. Rejected: silent invention of packages/services.
- Seeds/seed-regenerable artifacts gitignored; ground truth + questions + results committed as evaluation evidence. Fresh rebuild reproduces all numbers exactly. Rejected: committing 7 MB of regenerable seeds.
- Demo video left to the human (needs screen recording); `docs/demo-script.md` makes it mechanical. Rejected: claiming the video deliverable done.
- UI backend reuses agent/MCP functions directly; the refusal drill tampers a real proof and submits it through the real guardrail. Rejected: mock refusal message (would not prove the guardrail).
- Reachable services carry a second, verified **exposure proof** (shortest public Endpoint → ROUTES_TO → CALLS* route, every edge checked, start must be `public: true`), so "reachable" is backed by a path just as "affected" is. Rejected: a bare reachable boolean (unexplained, unauditable).
- The UI's Investigate panel streams the MCP agent over Server-Sent Events (stdlib, one-way, `EventSource` in the browser); the LLM call runs in a worker thread so the MCP session isn't blocked. Rejected: WebSockets (extra dependency for one-way data); polling (laggy trace).
- Agent findings need human approval in the UI, and only ACT_NOW findings whose verdict matches the rules *and* whose proof verified can be approved. Rejected: auto-acting on model output (the guardrail stops forged proofs, but a human should own outbound tickets).
- Tests that act write to a temp action log (`BLAST_ACTION_LOG`, inherited by spawned MCP servers) and delete the Decision nodes they created; `agent.reset_demo` clears both for a clean demo. Rejected: shared log/graph state (tests polluted the demo; 47 stray Decisions found).
- `.env` is loaded by a stdlib reader in `ingest/config.py` with real env taking precedence. Rejected: python-dotenv dependency for ten lines of parsing.
