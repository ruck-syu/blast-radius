// remove_imported_cve: delete CVEs imported by ingest.osv (never seeded ones).
// Params: $id ('' = every imported CVE).
MATCH (c:CVE {source: 'osv'}) WHERE $id = '' OR c.id = $id
DETACH DELETE c
RETURN count(c) AS removed
