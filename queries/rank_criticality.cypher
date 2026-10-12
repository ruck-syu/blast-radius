// rank_criticality: centrality over the service CALLS graph.
// NOTE: FalkorDB graph-algorithm procedure names must be verified against the
// FalkorDB docs before use (do not guess). This degree-based fallback runs
// today; a PageRank variant replaces it once the procedure name is confirmed.
MATCH (s:Service)
OPTIONAL MATCH (s)-[:CALLS]->(out:Service)
OPTIONAL MATCH (in:Service)-[:CALLS]->(s)
RETURN s.name AS service, count(DISTINCT out) AS out_degree, count(DISTINCT in) AS in_degree
ORDER BY in_degree DESC, out_degree DESC
