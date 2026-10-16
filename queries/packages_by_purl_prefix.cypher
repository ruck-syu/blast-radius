// packages_by_purl_prefix: every version of one package in the graph.
// Params: $prefix (purl without version, plus '@', e.g. 'pkg:maven/g/a@').
MATCH (p:Package) WHERE p.purl STARTS WITH $prefix
RETURN p.purl AS purl, p.version AS version
