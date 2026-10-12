// upgrade_depends: rewire Package DEPENDS_ON edges from an old version to its successor.
// Part of the simulate_fix upgrade path. Params: $old_purl, $new_purl.
MATCH (p:Package)-[r:DEPENDS_ON]->(old:Package {purl: $old_purl}), (new:Package {purl: $new_purl})
CREATE (p)-[:DEPENDS_ON]->(new)
DELETE r
