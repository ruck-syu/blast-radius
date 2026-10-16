// list_services: every service with its tier, for pickers in the UI.
MATCH (s:Service) RETURN s.name AS name, s.tier AS tier ORDER BY s.name
