# Benchmark methodology (Phase 7)

## Question bank

`benchmark/questions.py` generates 27 questions per org from planted ground
truth (`benchmark/ground_truth.json`) plus ownership facts from the seed files.
Groups: 1-hop (6, single lookups), 2–3-hop (8), 4–6-hop (7), counterfactual (6).
Kinds: `scalar` (exact match), `set` (precision/recall/F1), `ranked`
(P@k + MRR against reachable-as-relevant), `path` (endpoint accuracy + shared
edge-by-edge validity check reusing the guardrail queries).

Ranked relevance = reachability (the property a triage ranking must surface),
not risk-score order — so the metric tests whether risk ranking puts truly
exposed services first rather than reproducing its own scores.

## The three systems

1. **flat-lexical-tables** (`benchmark/systems/flat_sys.py`): stands in for
   the vector-RAG/flat-table baseline. Same seed data in SQLite, keyword entity
   matching, single-join SQL only (no recursive CTEs, no transitive closure).
   No embedding model is available in this offline environment; lexical
   retrieval over rows is the weaker-but-honest substitute, and the structural
   claim under test (flat retrieval loses multi-hop structure) does not depend
   on embedding quality.
2. **unbounded-cypher-proxy** (`benchmark/systems/cypher_sys.py`): stands in
   for free-form text-to-Cypher. No LLM key is configured here, so reported
   numbers use handwritten per-kind Cypher WITHOUT depth bounds and WITHOUT
   proof verification — the failure mode unconstrained generation degrades to.
   A real LLM writer (`llm_write`, Anthropic/OpenAI via env, read-only
   `RO_QUERY` enforced) runs with `--writer llm`; the `used_llm` flag in
   results records which mode produced the numbers (false for all runs here).
3. **agent-parameterized-tools** (`benchmark/systems/agent_sys.py`): the
   product — same MCP tool functions, depth-bounded traversal, rules, verified
   paths. Question adapters only select tools and read fields; no free-form
   Cypher.

## Held-out discipline

- Two separate graphs; all verdict/risk thresholds were fixed (Phases 2–3)
  before the benchmark existed. Nothing was tuned against dev results
  (the only post-run changes were outright adapter/question-generator bugs:
  mis-indexed columns, a wrong ground-truth entries list, an unhandled
  question field — each fixed for correctness, never for score).
  Two baseline gaps found the same way (a missing join, an unordered
  lookup) were fixed in the baselines' favor, raising their scores.
- CVE IDs overlap dev/held-out by construction (3 public advisories); the
  held-out services, packages, and edges are entirely unseen. Final numbers
  are reported on held-out.

## Ablation

`--ablate` disables `graph.run/run_on/connect`: the agent answers "unknown"
to all 27 questions (overall 0.000), showing which capabilities stop without
FalkorDB — all of them.

## Reproduce

```bash
python -m benchmark.questions              # rebuild question bank
python -m benchmark.runner --org all        # dev + heldout, all systems
python -m benchmark.runner --org heldout --ablate
```
