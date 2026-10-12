// check_decision: what a Decision node links to (ABOUT CVE/service, FIRED rules).
// Test/verification helper. Params: $id (Decision id).
MATCH (d:Decision {id: $id})-[t:ABOUT|FIRED]->(x)
RETURN coalesce(x.id, x.name) AS target, type(t) AS rel, labels(x) AS labels
