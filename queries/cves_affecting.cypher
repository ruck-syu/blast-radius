// cves_affecting: CVEs that affect one package version (e.g. an upgrade target).
// Params: $purl.
MATCH (c:CVE)-[:AFFECTS]->(:Package {purl: $purl})
RETURN c.id AS cve, c.in_kev AS in_kev, c.cvss AS cvss
ORDER BY cve
