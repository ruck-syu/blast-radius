// upgrade_path: the successor version of a package and the CVEs it fixes.
// Params: $old_purl. Empty result when the package has no upgrade path.
MATCH (old:Package {purl: $old_purl})-[:SUPERSEDED_BY]->(new:Package)
OPTIONAL MATCH (c:CVE)-[:FIXED_IN]->(new)
RETURN new.purl AS new_purl, collect(c.id) AS fixed_cves
