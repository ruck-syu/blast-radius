// check_reachability: whether a service is reachable from a public endpoint.
// Returns one row per public entry path, each with the full endpoint path.
// Params: $service (Service name), $max_call_depth (default 4, literal bound).
MATCH path = (e:Endpoint {public: true})-[:ROUTES_TO]->(entry:Service)-[:CALLS*0..4]->(s:Service {name: $service})
RETURN e.path AS entry_point, entry.name AS entry_service, path
