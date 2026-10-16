// cve_source: where a CVE node came from ('osv' for ingest.osv imports, null for
// seeded data). Params: $id. Empty result when the CVE is not in the graph.
MATCH (c:CVE {id: $id})
RETURN coalesce(c.source, 'seed') AS source
