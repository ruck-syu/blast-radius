// verify_edge: does an edge of the asserted type exist between two node ids?
// Guardrail primitive: every edge of a proof path must exist in the graph.
// Params: $src, $dst (node ids), $rel (edge type).
MATCH (a)-[r]->(b)
WHERE id(a) = $src AND id(b) = $dst AND type(r) = $rel
RETURN count(r) AS c
