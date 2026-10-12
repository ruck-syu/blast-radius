// list_decisions: recent Decision nodes with their CVE/service links and fired rules.
// No params; capped at 50 rows.
MATCH (d:Decision)
OPTIONAL MATCH (d)-[:ABOUT]->(c:CVE)
OPTIONAL MATCH (d)-[:ABOUT]->(s:Service)
OPTIONAL MATCH (d)-[:FIRED]->(r:Rule)
WITH d, collect(DISTINCT c.id)[0] AS cve, collect(DISTINCT s.name)[0] AS service,
     collect(DISTINCT r.id) AS rules
RETURN d.id AS id, d.timestamp AS ts, d.action AS action, d.verdict AS verdict,
       d.target AS target, cve, service, rules
ORDER BY ts DESC
LIMIT 50
