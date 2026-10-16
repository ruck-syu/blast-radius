# Demo script (~6 min screen recording)

Prereqs: `docker compose up -d`, data loaded (see README Setup),
`ANTHROPIC_API_KEY` in `.env` (for step 3), `python -m agent.reset_demo`
(clean Decisions, live changes, log), then `python -m ui.server` on :8765.
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
7. **Close (5:15).** Decisions recorded in the graph (ABOUT CVE/service,
   FIRED rules) and the action log with accepts and the refusal.

No key? Skip step 3; the header badge shows "Claude: no API key" and every
other step runs without it. `python -m agent.mcp_agent CVE-2021-44228` shows
the same trace in a terminal.
