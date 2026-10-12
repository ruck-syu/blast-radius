// remove_fixed_affects: drop AFFECTS edges a fixed version resolves, i.e. CVEs
// whose FIXED_IN points at the new version no longer affect the old version.
// Part of the simulate_fix upgrade path. Params: $old_purl, $new_purl.
MATCH (c:CVE)-[r:AFFECTS]->(old:Package {purl: $old_purl})
WHERE (c)-[:FIXED_IN]->(:Package {purl: $new_purl})
DELETE r
