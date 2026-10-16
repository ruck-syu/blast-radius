// import_fix_link: FIXED_IN to the fixed version plus SUPERSEDED_BY from the
// vulnerable one (the upgrade path simulate_fix follows). An upgrade edge that
// already exists is reused; one created here is tagged source 'osv' for removal.
// Params: $cve, $old_purl, $new_purl.
MATCH (c:CVE {id: $cve}), (old:Package {purl: $old_purl}), (new:Package {purl: $new_purl})
MERGE (c)-[:FIXED_IN]->(new)
MERGE (old)-[s:SUPERSEDED_BY]->(new)
ON CREATE SET s.source = 'osv'
RETURN c.id AS cve_id
