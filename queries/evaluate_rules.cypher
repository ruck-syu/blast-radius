// evaluate_rules: which named rules fire for a CVE+service pair, with weights.
// Rules are stored as Rule nodes; firing conditions are computed in Cypher
// from CVE flags, public reachability, tier/degree, and FIXED_IN presence.
// Params: $cve (CVE id), $service (Service name). Depth bounds are literals.
MATCH (c:CVE {id: $cve}), (s:Service {name: $service})
OPTIONAL MATCH (e:Endpoint {public: true})-[:ROUTES_TO]->(entry:Service)-[:CALLS*0..4]->(s)
WITH c, s, count(DISTINCT e) AS n_entries
OPTIONAL MATCH (s)-[:CALLS]->(out:Service)
OPTIONAL MATCH (inc:Service)-[:CALLS]->(s)
WITH c, s, n_entries, count(DISTINCT out) AS out_deg, count(DISTINCT inc) AS in_deg
OPTIONAL MATCH (c)-[:FIXED_IN]->(f:Package)
WITH c, s, n_entries, in_deg, count(f) > 0 AS fix_available
MATCH (r:Rule)
WITH r, CASE r.id
  WHEN 'R_KEV' THEN c.in_kev
  WHEN 'R_PUBLIC_REACH' THEN n_entries > 0
  WHEN 'R_CRITICAL_TIER' THEN s.tier = 'critical' OR in_deg >= 3
  WHEN 'R_NO_REACH' THEN n_entries = 0
  WHEN 'R_FIX_AVAILABLE' THEN fix_available
  ELSE false END AS fired
RETURN r.id AS rule, r.weight AS weight, fired
ORDER BY rule
