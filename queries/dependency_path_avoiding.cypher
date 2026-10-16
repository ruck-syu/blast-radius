// dependency_path_avoiding: shortest USES/DEPENDS_ON* path from $service to the package
// $cve AFFECTS that passes through none of $removed (purls the service no longer resolves).
// Params: $cve, $service, $removed (list of purls). No row = the change removes the CVE.
MATCH (c:CVE {id: $cve})-[:AFFECTS]->(vuln:Package)
MATCH dep = (s:Service {name: $service})-[:USES]->(:Package)-[:DEPENDS_ON*0..6]->(vuln)
WHERE none(n IN nodes(dep) WHERE coalesce(n.purl, '') IN $removed)
RETURN dep AS path, length(dep) AS depth
ORDER BY depth ASC
LIMIT 1
