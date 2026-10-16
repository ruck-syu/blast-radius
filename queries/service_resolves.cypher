// service_resolves: is $purl anywhere in $service's dependency tree (USES then DEPENDS_ON*)?
// Params: $service (name), $purl. Same depth bound as score_risk.
MATCH (:Service {name: $service})-[:USES]->(:Package)-[:DEPENDS_ON*0..6]->(p:Package {purl: $purl})
RETURN count(p) > 0 AS resolves
