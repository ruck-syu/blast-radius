# AI_USAGE.md

Disclosure of AI assistant usage (per competition rules).

| Date | Tool | Use |
|------|------|-----|
| 2026-10-12 | OpenCode (Muse Spark) | Scaffolded repo layout, docker-compose, synthetic generator, ingestion, queries, verification |
| 2026-10-12 | OpenCode (Muse Spark) | Phase 2: queries/score_risk.cypher, mcp_server (graph helper + 6 FastMCP tools), test_tools.py acceptance |
| 2026-10-12 | OpenCode (Muse Spark) | Phase 3: evaluate_rules query+tool, agent loop (triage/verify/verdicts/LLM hook), test_agent.py acceptance |
| 2026-10-12 | OpenCode (Muse Spark) | Phase 4: sandbox simulation (GRAPH.COPY per docs), simulate_fix tool, fix comparison + recommendation, test_simulation.py acceptance |
| 2026-10-12 | OpenCode (Muse Spark) | Phase 5: proof-path guardrail + Decision nodes, 3 action tools (env-gated delivery), agent act flow, test_actions.py acceptance |
| 2026-10-12 | OpenCode (Muse Spark) | Phase 6: stdlib UI server + single-page console (ranked list, SVG paths, sim view, action log, refusal drill), HTTP + render-harness verification |
| 2026-10-12 | OpenCode (Muse Spark) | Phase 7: question bank (27/org), 3 benchmark systems, runner + metrics + ablation, results table + methodology |
| 2026-10-12 | OpenCode (Muse Spark) | Phase 8: apply_change tool, full README per spec s9, demo script, fresh-machine rebuild validation, repo commit |
| 2026-10-15 | Claude Code (Claude Opus 5.5) | Track-fit gaps: MCP-client agent with model-driven tool selection + reason trace, PageRank/betweenness criticality, get_cve tool, write_decision empty-rules fix, test_mcp_agent.py acceptance |
| 2026-10-17 | Claude Code (Claude Opus 5.5) | Verified exposure proofs, UI redesign (blast map, attack chain, live Investigate over SSE with human approval), test isolation + reset_demo, `.env` loading, ui/test_ui.py acceptance |
| 2026-10-17 | Claude Code (Claude Opus 5.5) | Live change panel + agent.live (provenance-tagged apply/revert), assess_change sandbox pre-merge gate (MCP tool, agent.gate CLI, UI sandbox check), .mcp.json, test_gate.py acceptance |
| 2026-10-17 | Claude Code (Claude Opus 5.5) | Call-graph centrality in triage (exact betweenness, checked against a Brandes reference), gate removals as path avoidance, CycloneDX SBOM diff in agent.gate, agent.sbom exporter, UI pin-fixed-version sandbox check, sandbox-verified fix PRs, offline planner for keyless runs, OSV.dev advisory import (CLI + UI), carried-exposure warnings on fixes, org posture roll-up (MCP tool, CLI, UI) |
