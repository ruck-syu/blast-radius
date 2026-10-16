// verify_public_endpoint: is the node id a public Endpoint?
// Anchors the start of an exposure proof (Endpoint -ROUTES_TO-> ... -> Service).
// Params: $nid (node id).
MATCH (e:Endpoint {public: true})
WHERE id(e) = $nid
RETURN count(e) AS c
