// call_graph_edges: the Service CALLS relationships underpinning rank_criticality.
// Returned as path evidence alongside the centrality ranking. No params.
MATCH (a:Service)-[r:CALLS]->(b:Service)
RETURN a.name AS caller, b.name AS callee
