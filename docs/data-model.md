# Data model

Implements spec section 4. Nodes: `CVE`, `Package`, `Service`, `Endpoint`,
`Team`, `Person`, `Deployment`, `Rule`, (`Decision` from Phase 5).
Edges: `AFFECTS {range}`, `DEPENDS_ON`, `USES`, `CALLS`, `ROUTES_TO`,
`OWNED_BY`, `MEMBER_OF`, `DEPLOYED`, `OF`, `FIXED_IN`, `SUPERSEDED_BY`
(`ABOUT`, `FIRED` from Phase 5).

```
(CVE)-[:AFFECTS {range}]->(Package)
(Package)-[:DEPENDS_ON]->(Package)
(Service)-[:USES]->(Package)
(Service)-[:CALLS]->(Service)
(Endpoint)-[:ROUTES_TO]->(Service)
(Service)-[:OWNED_BY]->(Team)
(Person)-[:MEMBER_OF]->(Team)
(Person)-[:DEPLOYED]->(Deployment)
(Deployment)-[:OF]->(Service)
(CVE)-[:FIXED_IN]->(Package)
(Package)-[:SUPERSEDED_BY]->(Package)
```

Indexes: `CVE.id`, `Package.purl`, `Service.name`.

## Data sources

- CVE metadata (ids, cvss/epss/KEV, summaries): public advisory data.
- Package dependency edges: synthetic, shaped like real lockfiles
  (seeded DAG with direct + transitive deps, `synthetic:true` where fictional).
- Org layer (services, endpoints, teams, people, deployments): fully synthetic,
  fictional names, `synthetic:true`. Two orgs: `dev` (seed 42) and held-out
  (seed 1337) in separate graphs `blast_radius_dev` / `blast_radius_heldout`.

## Scale (Phase 1 record)

| graph | nodes | edges |
|-------|-------|-------|
| blast_radius_dev | 22234 | 39096 |
| blast_radius_heldout | 22240 | 39214 |

Queries the product depends on: `queries/*.cypher`.
Ground truth: `benchmark/ground_truth.json`.
