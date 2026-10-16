# Demo script (~6.5 min screen recording)

Prereqs: `docker compose up -d`, data loaded (see README Setup),
`ANTHROPIC_API_KEY` in `.env` (for step 3), `python -m agent.reset_demo`
(clean Decisions, live changes, imported CVEs, log), then `python -m ui.server` on :8765.
Use CVE-2021-44228, dev org.

1. **Blast radius (0:00).** Triage loads on open. Narrate the tiles: 15
   affected services through transitive dependencies, 7 reachable from the
   internet, 6 ACT_NOW. On the blast map, hover a red service: its public
   endpoint, every dependency hop down to log4j-core, and the CVE light up.
2. **Why, with proof (0:45).** Click the top ranked row. Read the attack
   chain: public route (endpoint → CALLS → service) and dependency chain
   (service → USES → DEPENDS_ON* → log4j-core → CVE), both *verified* edge by
   edge against FalkorDB. Point at risk = severity × exposure × criticality,
   the fired rules, and the owner.
3. **Claude investigates over MCP (1:30).** Ask "How does public traffic
   reach d-checkout-api, and who should fix it?" or leave it blank for a full
   triage. Each tool Claude picks streams in with its reason and what came
   back. The findings table shows whether each verdict matches the rules and
   each proof verified. Approve: tickets + notifications for those only.
4. **Live change, no retraining (2:45).** Live change card: *Expose to the
   internet* a critical SCHEDULE service, Apply. ~250 ms later it is ACT_NOW
   with a verified route through the new `/live/...` endpoint, tagged
   "was SCHEDULE" and highlighted on the map. *Adopt the vulnerable package*
   on an unaffected service: it joins the blast radius. Revert live changes.
5. **Simulation (3:45).** Simulate fixes. Each upgrade runs in a sandbox copy
   of the graph; narrate the before/after bars and the recommendation (largest
   org-wide risk reduction), with numbers.
6. **Guardrail refusal (4:30).** Ticket + notify ACT_NOW, then the guardrail
   drill: a forged proof comes back refused with the missing edge named. "No
   path, no action."
7. **A CVE published today (5:15).** Type CVE-2021-45046 (not in the seed
   data), Triage: "not present". *Import from OSV.dev*: the real advisory's
   range (>=2.13.0 <2.16.0) is matched against the graph's log4j versions,
   CVSS 9.0 from the vector, CISA KEV yes, and it is triaged at once.
   *Roll up all CVEs* (Org posture): log4j 2.14.1 tops the package list with
   its upgrade target in the graph; click a service's CVE to jump into triage.
8. **Close (5:45).** Decisions recorded in the graph (ABOUT CVE/service,
   FIRED rules) and the action log with accepts and the refusal.

No key? In step 3 click *Offline planner (no model)* instead: the same MCP
loop, trace, checks and Approve, driven by a fixed tool sequence and labelled
as such. `python -m agent.mcp_agent CVE-2021-44228 [--offline]` shows the same
trace in a terminal.
