// verify_path_cve_anchor: is the node id a package the CVE affects?
// Binds a dependency proof's end node to the claimed CVE.
// Params: $cve (id), $nid (node id).
MATCH (c:CVE {id: $cve})-[:AFFECTS]->(p)
WHERE id(p) = $nid
RETURN count(p) AS c
