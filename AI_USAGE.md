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
