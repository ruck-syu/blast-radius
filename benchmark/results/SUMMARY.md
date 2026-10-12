# Benchmark results (Phase 7)

27 questions per org (6 × 1-hop, 8 × 2–3-hop, 7 × 4–6-hop, 6 × counterfactual),
identical questions per system. Final numbers are the **held-out** column
(new graph, unseen during development). No tuning was performed on either
org — thresholds were fixed before the first benchmark run — so dev ≈ held-out
is expected, not evidence of overfitting. Small benchmark → modest claims only.

## Overall score by group (held-out first)

| system | overall | 1-hop | 2–3-hop | 4–6-hop | counterfactual |
|--------|---------|-------|---------|---------|----------------|
| agent-parameterized-tools (held-out) | **0.998** | 1.000 | 0.993 | 1.000 | 1.000 |
| agent-parameterized-tools (dev) | 0.995 | 1.000 | 0.982 | 1.000 | 1.000 |
| unbounded-cypher-proxy (held-out) | 0.632 | 1.000 | 0.731 | 0.579 | 0.194 |
| unbounded-cypher-proxy (dev) | 0.685 | 1.000 | 0.712 | 0.543 | 0.500 |
| flat-lexical-tables (held-out) | 0.293 | 0.667 | 0.239 | 0.000 | 0.333 |
| flat-lexical-tables (dev) | 0.227 | 0.667 | 0.236 | 0.000 | 0.042 |
| agent, graph removed (ablation, held-out) | **0.000** | 0.000 | 0.000 | 0.000 | 0.000 |

## Metrics detail (held-out)

| system | scalar acc | set P / R / F1 | ranked P@k / MRR | path cited → valid | avg calls | avg ms |
|--------|-----------|----------------|------------------|--------------------|-----------|--------|
| agent | 1.000 | 1.000 / 0.990 / 0.995 | 1.000 / 1.000 | 1.000 → **1.000** | 1.8 | 46.9 |
| unbounded-cypher | 0.692 | 0.600 / 0.700 / 0.627 | 0.422 / 0.778 | 0.000 → n/a | 1.1 | 10.9 |
| flat-lexical | 0.462 | 0.083 / 0.100 / 0.091 | 0.333 / 0.333 | 0.000 → n/a | 2.8 | 0.0 |

## What the numbers say

- Flat tables answer single lookups (owner, tier, "is clean service affected: no")
  but score **0.0 on every 4–6-hop question**: without transitive closure the
  15-service blast radii are invisible (single-hop affected sets are empty —
  no service directly USEs a vulnerable package).
- Unbounded Cypher degrades with hop count and never cites a verifiable path
  (path validity n/a by design — no proof check). Its ranked lists often lead
  with a reachable service (MRR 0.78) but are unordered (`LIMIT` without
  `ORDER BY` → P@k 0.42). Counterfactuals are guesses without a simulator.
- The agent's only misses anywhere (dev + held-out) are entry-service recall
  on one question (P=1.0, R=0.75–0.9): entries reachable only via >4 CALLS hops
  fall outside the `max_call_depth=4` bound. That is the measured cost of the
  depth bound — precision stays 1.0 throughout (set precision 1.000).
- Graph-removed ablation: 27/27 errors, every group 0.000. The product does
  not function without FalkorDB, per the spec's hard constraint.

## Honesty notes

- 27 questions × 2 orgs. Small benchmark; claims are correspondingly modest.
- The text-to-Cypher column is the documented no-LLM proxy (handwritten
  unbounded templates), not live LLM output — no key is configured here.
  Run `python -m benchmark.runner --writer llm` with a key for the real thing.
- CVE IDs overlap between dev and held-out graphs by construction (3 public
  advisory IDs); the held-out *graph* (services, packages, edges) is unseen.
  See `benchmark/METHODOLOGY.md`.
