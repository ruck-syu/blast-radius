// service_sbom: every package in $service's resolved dependency tree (USES then
// DEPENDS_ON*, same depth bound as score_risk), flagged direct when USES points at it.
// Params: $service (name).
MATCH (s:Service {name: $service})-[:USES]->(d:Package)
WITH s, collect(DISTINCT d.purl) AS direct
MATCH (s)-[:USES]->(:Package)-[:DEPENDS_ON*0..6]->(p:Package)
RETURN DISTINCT p.purl AS purl, p.name AS name, p.version AS version, p.purl IN direct AS direct
ORDER BY purl
