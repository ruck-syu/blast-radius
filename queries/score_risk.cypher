// score_risk: ranked list using risk = severity x exposure x criticality.
// severity from CVE (cvss, epss, in_kev); exposure from public reachability;
// criticality from tier + call-graph degree. All computed in Cypher.
// Params: $cve (CVE id). Depth bounds are literals (see DECISIONS.md).
MATCH (c:CVE {id: $cve})-[:AFFECTS]->(vuln:Package)
MATCH dep = (s:Service)-[:USES]->(:Package)-[:DEPENDS_ON*0..6]->(vuln)
WITH s, c, dep, length(dep) AS d ORDER BY d ASC
WITH s, c, collect(dep)[0] AS dep, min(d) AS depth
OPTIONAL MATCH (e:Endpoint {public: true})-[:ROUTES_TO]->(entry:Service)-[:CALLS*0..4]->(s)
WITH s, c, dep, depth, count(DISTINCT e) AS n_entries, collect(DISTINCT e.path)[0] AS entry_point
OPTIONAL MATCH (s)-[:CALLS]->(out:Service)
OPTIONAL MATCH (inc:Service)-[:CALLS]->(s)
WITH s, c, dep, depth, n_entries, entry_point, count(DISTINCT out) AS out_deg, count(DISTINCT inc) AS in_deg
WITH s, dep, depth, n_entries, entry_point, out_deg, in_deg,
  (c.cvss / 10.0) * (1.0 + c.epss) * (CASE WHEN c.in_kev THEN 2.0 ELSE 1.0 END) AS severity,
  (CASE WHEN n_entries > 0 THEN 2.0 ELSE 0.5 END) AS exposure,
  ((CASE s.tier WHEN 'critical' THEN 2.0 WHEN 'standard' THEN 1.0 ELSE 0.5 END) + 0.1 * (in_deg + out_deg)) AS criticality
RETURN s.name AS service, s.tier AS tier, depth, severity, exposure, criticality,
  severity * exposure * criticality AS risk, n_entries > 0 AS reachable, entry_point, dep AS path
ORDER BY risk DESC
