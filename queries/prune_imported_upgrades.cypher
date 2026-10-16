// prune_imported_upgrades: drop upgrade edges ingest.osv created once no CVE
// is FIXED_IN their target any more. No params.
MATCH (:Package)-[s:SUPERSEDED_BY {source: 'osv'}]->(new:Package)
OPTIONAL MATCH (c:CVE)-[:FIXED_IN]->(new)
WITH s, count(c) AS users WHERE users = 0
DELETE s
RETURN count(*) AS pruned
