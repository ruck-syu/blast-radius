// apply_add_deployment: record a new deployment of a service by a person.
// Params: $id, $service (name), $version, $by (person handle), $timestamp.
MATCH (s:Service {name: $service}), (p:Person {handle: $by})
CREATE (d:Deployment {id: $id, timestamp: $timestamp, version: $version, synthetic: true})
CREATE (p)-[:DEPLOYED]->(d)
CREATE (d)-[:OF]->(s)
RETURN id(d) AS deployment_id
