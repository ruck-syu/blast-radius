# Demo script (~5 min screen recording)

Prereqs: `docker compose up -d`, data loaded (see README Setup),
`python -m ui.server` running on :8765. Use CVE-2021-44228, dev org.

1. **Ranked triage (0:00).** Enter the CVE, Triage. Narrate: 15 raw matches
   narrow to 6 reachable critical services, each with its graph path. Click
   the top row; scroll the SVG proof path (Service → USES → DEPENDS_ON* →
   vulnerable package), point at the verified badge, rules, and owner.
2. **Simulation (1:30).** Simulate fixes. Narrate the three before/after bars
   and the recommendation (largest risk reduction), with numbers.
3. **Actions with proof (2:30).** Ticket + notify ACT_NOW. Show accepted
   entries with decision IDs in the action log.
4. **Guardrail refusal (3:15).** Guardrail drill: forged proof comes back
   refused with the reason; show it red in the log. "No path, no action."
5. **Live change, no retraining (4:00).** In a terminal:
   `python -m mcp_server.server` … simpler: run
   `python -c "from mcp_server.server import apply_change; print(apply_change('add_endpoint', 'dev', path='/api/d/v1/demo', public=True, service='<an-unreachable-affected-service>'))"`
   then re-triage in the UI and show the newly reachable service. Delete the
   endpoint afterward (see `mcp_server/test_apply.py` revert pattern).
6. **Verdicts + rules (4:40).** Scroll two results: an ACT_NOW (KEV +
   public reach) and a SCHEDULE (KEV but no public path) with fired rules.
7. **Close (5:00).** Action log + decisions; note every entry links a
   Decision node (ABOUT CVE/service, FIRED rules) in FalkorDB.
