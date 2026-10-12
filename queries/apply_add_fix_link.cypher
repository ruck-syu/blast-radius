// apply_add_fix_link: link a CVE to its fixed package version (FIXED_IN plus
// SUPERSEDED_BY from the vulnerable version, giving simulate_fix an upgrade path).
// Params: $cve (id), $old_purl (vulnerable), $new_purl (fixed).
MATCH (c:CVE {id: $cve}), (old:Package {purl: $old_purl}), (new:Package {purl: $new_purl})
CREATE (c)-[:FIXED_IN]->(new)
CREATE (old)-[:SUPERSEDED_BY]->(new)
RETURN c.id AS cve_id
