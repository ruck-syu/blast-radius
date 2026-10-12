// upgrade_uses: rewire Service USES edges from an old package version to its successor.
// Part of the simulate_fix upgrade path. Params: $old_purl, $new_purl.
MATCH (s:Service)-[r:USES]->(old:Package {purl: $old_purl}), (new:Package {purl: $new_purl})
CREATE (s)-[:USES]->(new)
DELETE r
