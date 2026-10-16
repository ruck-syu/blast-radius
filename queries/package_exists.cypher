// package_exists: whether a package with this purl is in the graph.
// Params: $purl. One row: count (0 or 1).
MATCH (p:Package {purl: $purl}) RETURN count(p) AS c
