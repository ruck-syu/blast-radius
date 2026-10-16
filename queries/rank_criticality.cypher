// rank_criticality: graph-algorithm centrality over the service CALLS graph.
// PageRank (algo.pageRank) ranks services that many important services depend on;
// betweenness (algo.betweenness) flags choke points on call paths; degrees are
// kept as human-readable evidence. Procedure names verified live via dbms.procedures().
// algo.betweenness samples source nodes by default (approximate scores); samplingSize
// above the service count makes it exact Brandes. Each algorithm runs once.
CALL algo.pageRank('Service', 'CALLS') YIELD node, score
WITH collect({s: node, pagerank: score}) AS pr
CALL algo.betweenness({nodeLabels: ['Service'], relationshipTypes: ['CALLS'], samplingSize: 100000}) YIELD node, score
UNWIND pr AS p
WITH p.s AS s, p.pagerank AS pagerank, node, score WHERE node = s
WITH s, pagerank, score AS betweenness
OPTIONAL MATCH (s)-[:CALLS]->(out:Service)
OPTIONAL MATCH (in:Service)-[:CALLS]->(s)
RETURN s.name AS service, count(DISTINCT out) AS out_degree, count(DISTINCT in) AS in_degree,
  pagerank, betweenness
ORDER BY pagerank DESC, betweenness DESC, in_degree DESC
