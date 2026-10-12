// find_owner: team, Slack channel, and most recent deployer of a service,
// plus the ownership and deploy paths as graph evidence.
// Params: $service (Service name).
MATCH own = (s:Service {name: $service})-[:OWNED_BY]->(t:Team)
OPTIONAL MATCH dep = (p:Person)-[:DEPLOYED]->(d:Deployment)-[:OF]->(s)
RETURN t.name AS team, t.slack_channel AS channel,
       p.name AS last_deployer, d.timestamp AS deployed_at, own AS ownership_path, dep AS deploy_path,
       s.tier AS tier
ORDER BY d.timestamp DESC LIMIT 1
