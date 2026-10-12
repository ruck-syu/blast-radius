// dependency_path: the explanation path from CVE to a service.
// Params: $cve (CVE id), $service (Service name), $max_dep_depth (default 6).
MATCH (c:CVE {id: $cve})-[:AFFECTS]->(vuln:Package)
MATCH path = (s:Service {name: $service})-[:USES]->(:Package)-[:DEPENDS_ON*0..6]->(vuln)
RETURN path, length(path) AS depth
ORDER BY depth ASC
LIMIT 1
