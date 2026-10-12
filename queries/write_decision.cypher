// write_decision: record an accepted action as a Decision node linked to the
// CVE and service (ABOUT) and the fired rules (FIRED). proof_path is the
// serialized node-id list. Params: $id, $timestamp, $verdict, $rationale,
// $proof_ids (int list), $action, $target, $cve, $service, $rules (id list).
MATCH (c:CVE {id: $cve}), (s:Service {name: $service})
CREATE (d:Decision {id: $id, timestamp: $timestamp, verdict: $verdict,
  rationale: $rationale, proof_path: $proof_ids, action: $action, target: $target})
CREATE (d)-[:ABOUT]->(c)
CREATE (d)-[:ABOUT]->(s)
WITH d
UNWIND $rules AS rid
MATCH (r:Rule {id: rid})
CREATE (d)-[:FIRED]->(r)
RETURN d.id AS id
