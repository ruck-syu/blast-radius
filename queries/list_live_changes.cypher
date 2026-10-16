// list_live_changes: endpoints and USES edges written by apply_change with a given provenance tag.
// Params: $source. One row per change: kind, what (path or purl), service.
MATCH (e:Endpoint {source: $source})-[:ROUTES_TO]->(s:Service)
RETURN 'expose' AS kind, e.path AS what, s.name AS service
UNION ALL
MATCH (s:Service)-[r:USES {source: $source}]->(p:Package)
RETURN 'adopt' AS kind, p.purl AS what, s.name AS service
