// import_cve: upsert an advisory imported from OSV and link the affected package
// versions. Params: $id, $cvss, $epss, $in_kev, $summary, $published, $osv_id,
// $affects (list of {purl, range}).
MERGE (c:CVE {id: $id})
SET c.cvss = $cvss, c.epss = $epss, c.in_kev = $in_kev, c.summary = $summary,
    c.published = $published, c.source = 'osv', c.osv_id = $osv_id
WITH c
UNWIND $affects AS a
MATCH (v:Package {purl: a.purl})
MERGE (c)-[r:AFFECTS]->(v)
SET r.range = a.range
RETURN count(v) AS linked
