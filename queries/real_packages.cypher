// real_packages: packages with real-world identities (not generator filler),
// the ones worth asking an advisory database about. No params.
MATCH (p:Package) WHERE coalesce(p.synthetic, false) = false
RETURN p.purl AS purl
