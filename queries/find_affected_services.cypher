// find_affected_services: transitive traversal from CVE to services.
// One row per service with its shortest proof path.
// Params: $cve (CVE id), $max_dep_depth (default 6, literal bound).
MATCH (c:CVE {id: $cve})-[:AFFECTS]->(vuln:Package)
MATCH path = (s:Service)-[:USES]->(:Package)-[:DEPENDS_ON*0..6]->(vuln)
WITH s, path, length(path) AS d ORDER BY d ASC
WITH s, collect(path)[0] AS path, min(d) AS depth
RETURN s.name AS service, depth, path
ORDER BY depth ASC
