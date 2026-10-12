// apply_add_endpoint: a new endpoint routing to a service.
// Params: $path, $public (bool), $service (name). Returns the endpoint node id.
MATCH (s:Service {name: $service})
CREATE (e:Endpoint {path: $path, public: $public, synthetic: true})-[:ROUTES_TO]->(s)
RETURN id(e) AS endpoint_id
