// apply_add_cve: a new CVE affecting a package.
// Params: $id, $cvss, $epss, $summary, $published, $affects_purl, $range.
MATCH (v:Package {purl: $affects_purl})
CREATE (c:CVE {id: $id, cvss: $cvss, epss: $epss, in_kev: false,
  summary: $summary, published: $published})
CREATE (c)-[:AFFECTS {range: $range}]->(v)
RETURN c.id AS cve_id
