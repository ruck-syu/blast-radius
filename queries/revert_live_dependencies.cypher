// revert_live_dependencies: delete USES edges written by apply_change with a given provenance tag.
// Params: $source. Returns how many were deleted.
MATCH (:Service)-[r:USES {source: $source}]->(:Package) WITH r, id(r) AS i DELETE r RETURN count(i) AS deleted
