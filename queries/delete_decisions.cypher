// delete_decisions: remove Decision nodes (and their ABOUT/FIRED edges) by id.
// Used only by test isolation and the demo reset. Params: $ids (list of Decision ids).
MATCH (d:Decision) WHERE d.id IN $ids
WITH d, d.id AS id
DETACH DELETE d
RETURN count(id) AS deleted
