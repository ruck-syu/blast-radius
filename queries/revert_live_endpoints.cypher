// revert_live_endpoints: delete endpoints written by apply_change with a given provenance tag.
// Params: $source. Returns how many were deleted.
MATCH (e:Endpoint {source: $source}) WITH e, e.path AS p DETACH DELETE e RETURN count(p) AS deleted
