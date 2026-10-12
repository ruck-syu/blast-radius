// get_cve: CVE metadata plus the vulnerable and fixed package purls.
// Params: $cve (CVE id). Empty result when the CVE is not in the graph.
MATCH (c:CVE {id: $cve})-[:AFFECTS]->(v:Package)
OPTIONAL MATCH (c)-[:FIXED_IN]->(f:Package)
RETURN c.id AS id, c.cvss AS cvss, c.epss AS epss, c.in_kev AS in_kev,
       c.summary AS summary, v.purl AS vuln_purl, f.purl AS fixed_purl
