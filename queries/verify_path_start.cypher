// verify_path_start: is the node id the claimed Service node?
// Params: $service (name), $nid (node id).
MATCH (s:Service {name: $service})
WHERE id(s) = $nid
RETURN count(s) AS c
