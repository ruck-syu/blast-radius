// decision_ids: ids of every Decision node (test isolation + demo reset). No params.
MATCH (d:Decision)
RETURN d.id AS id
