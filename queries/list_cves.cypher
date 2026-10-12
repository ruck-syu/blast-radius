// list_cves: all CVE IDs in the graph. No params.
MATCH (c:CVE)
RETURN c.id AS id
ORDER BY id
