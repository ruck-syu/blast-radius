// apply_add_dependency: a service USEs a package (both must already exist).
// Params: $service (name), $purl. Returns the created edge id.
MATCH (s:Service {name: $service}), (p:Package {purl: $purl})
CREATE (s)-[r:USES]->(p)
RETURN id(r) AS edge_id
