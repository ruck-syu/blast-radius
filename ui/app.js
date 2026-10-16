/* Blast Radius UI: blast map, ranked list, attack chains, Claude investigation,
   simulation, actions, decisions, log. No deps. */
const $ = (id) => document.getElementById(id);
const state = { triage: null, selected: 0, compare: null, config: {}, findings: null,
  services: [], changed: null };
const cve = () => $("cve").value.trim().toUpperCase();
const org = () => $("org").value;

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
const post = (path, body) => api(path, { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const label0 = (n) => (n.labels || ["?"])[0];

function shortLabel(n) {
  const p = n.properties || {};
  if (label0(n) === "Package") return `${p.name}@${p.version}`;
  return p.name || p.path || p.id || p.handle || "?";
}
const COLORS = { Service:"#58a6ff", Package:"#d29922", CVE:"#f85149", Endpoint:"#3fb950" };
const VCOLOR = { ACT_NOW:"#f85149", SCHEDULE:"#d29922", SUPPRESS:"#3fb950" };

/* ---------- summary ---------- */
function renderSummary() {
  const t = state.triage, el = $("summary");
  if (!t) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  if (!t.known_cve) { el.innerHTML = `<b>${esc(t.summary)}</b>`; return; }
  const c = t.cve, rs = t.results, n = (v) => rs.filter((r) => r.verdict === v).length;
  const tile = (k, v, cls = "") => `<div class="tile ${cls}"><b>${v}</b><span>${k}</span></div>`;
  el.innerHTML =
    `<p><b>${esc(c.id)}</b> <span class="kv">${esc(c.summary)}</span></p>` +
    `<div class="tiles">` +
    tile("affected services", rs.length) +
    tile("reachable from internet", rs.filter((r) => r.reachable).length) +
    tile("ACT_NOW", n("ACT_NOW"), "t-act") + tile("SCHEDULE", n("SCHEDULE"), "t-sched") +
    tile("SUPPRESS", n("SUPPRESS"), "t-supp") +
    tile("CVSS", c.cvss) + tile("EPSS", c.epss) + tile("CISA KEV", c.in_kev ? "yes" : "no", c.in_kev ? "t-act" : "") +
    `</div><p class="kv">${t.plan.length} graph tool calls · ${t.total_latency_ms}ms · ` +
    `vulnerable ${esc(c.vuln_purl)} → fixed ${esc(c.fixed_purl)}</p>`;
}

/* ---------- blast map: layered DAG of every proof + public route ---------- */
function renderMap() {
  const t = state.triage, el = $("map");
  if (!t || !t.known_cve || !t.results.length) { el.innerHTML = "<p class='hint'>Nothing affected.</p>"; return; }
  const nodes = new Map(), edges = new Map();
  const addNode = (id, info) => { if (!nodes.has(id)) nodes.set(id, { id, svcs: new Set(), ...info }); return nodes.get(id); };
  const addEdge = (a, b, type, svc, dashed = false) => {
    const k = `${a}>${b}`;
    if (!edges.has(k)) edges.set(k, { a, b, type, dashed, svcs: new Set() });
    edges.get(k).svcs.add(svc);
  };
  let maxD = 0;
  const cveId = "cve";
  t.results.forEach((r, i) => {
    const p = r.proof.path, last = p.nodes.length - 1;
    p.nodes.forEach((n, idx) => {
      const d = last - idx;  // distance from the vulnerable package
      if (idx === 0) {
        addNode(n.id, { kind: "svc", label: r.service, verdict: r.verdict, i, risk: r.risk }).svcs.add(r.service);
      } else {
        const nd = addNode(n.id, { kind: "pkg", label: shortLabel(n), d: 0 });
        nd.d = Math.max(nd.d, d); nd.svcs.add(r.service); maxD = Math.max(maxD, d);
      }
      if (idx > 0) addEdge(p.nodes[idx - 1].id, n.id, p.edges[idx - 1].type, r.service);
    });
    addNode(cveId, { kind: "cve", label: t.cve.id }).svcs.add(r.service);
    addEdge(p.nodes[last].id, cveId, "AFFECTED BY", r.service);
    const ex = r.exposure && r.exposure.path;
    if (ex) {
      const ep = ex.nodes[0], hops = ex.length - 1;
      addNode(`ep${ep.id}`, { kind: "ep", label: ep.properties.path }).svcs.add(r.service);
      addEdge(`ep${ep.id}`, p.nodes[0].id, hops ? `via ${hops} call${hops > 1 ? "s" : ""}` : "ROUTES_TO", r.service, hops > 0);
    }
  });
  // columns: 0 endpoints | 1 services | 2.. packages (far→near vuln) | vuln | CVE
  const colOf = (n) => n.kind === "ep" ? 0 : n.kind === "svc" ? 1 : n.kind === "cve" ? maxD + 3 : 2 + (maxD - n.d);
  const cols = [];
  nodes.forEach((n) => { (cols[colOf(n)] ||= []).push(n); });
  const ROW = 30, W = Math.max(el.clientWidth, 900), ncol = maxD + 4, CW = W / ncol, BW = Math.min(CW - 28, 210);
  const H = Math.max(...cols.map((c) => (c || []).length)) * ROW + 30;
  // order: services by risk, then barycenter sweeps so edges cross less
  (cols[1] || []).sort((a, b) => b.risk - a.risk);
  const place = (col) => (col || []).forEach((n, k) => { n.y = 18 + k * ROW + (H - 30 - col.length * ROW) / 2; });
  place(cols[1]);
  const neigh = (n) => [...edges.values()].filter((e) => e.a === n.id || e.b === n.id)
    .map((e) => nodes.get(e.a === n.id ? e.b : e.a)).filter((m) => m.y !== undefined);
  const sweep = (c) => { if (!cols[c]) return;
    cols[c].forEach((n) => { const ns = neigh(n); n.bc = ns.length ? ns.reduce((s, m) => s + m.y, 0) / ns.length : 0; });
    cols[c].sort((a, b) => a.bc - b.bc); place(cols[c]); };
  for (let c = 2; c < ncol; c++) sweep(c);
  sweep(0);
  cols.forEach((col, c) => (col || []).forEach((n) => { n.x = c * CW + (CW - BW) / 2; }));

  let s = `<svg class="map" viewBox="0 0 ${W} ${H}" style="height:${H}px">`;
  const heads = ["public endpoint", "affected service"];
  for (let c = 2; c <= maxD + 2; c++) heads.push(c === maxD + 2 ? "vulnerable package" : "dependency");
  heads.push("CVE");
  heads.forEach((h, c) => { s += `<text class="colh" x="${c * CW + CW / 2}" y="10">${h}</text>`; });
  edges.forEach((e) => {
    const a = nodes.get(e.a), b = nodes.get(e.b);
    const x1 = a.x + BW, y1 = a.y + 10, x2 = b.x, y2 = b.y + 10, mx = (x1 + x2) / 2;
    s += `<path class="edge${e.dashed ? " dashed" : ""}" data-svcs="${esc([...e.svcs].join(" "))}" ` +
         `d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"><title>${esc(e.type)}</title></path>`;
  });
  nodes.forEach((n) => {
    const color = n.kind === "svc" ? VCOLOR[n.verdict] : n.kind === "ep" ? COLORS.Endpoint
      : n.kind === "cve" ? COLORS.CVE : COLORS.Package;
    const maxc = Math.floor(BW / 6.4), txt = n.label.length > maxc ? n.label.slice(0, maxc - 1) + "…" : n.label;
    s += `<g class="node ${n.kind}" data-svcs="${esc([...n.svcs].join(" "))}"${n.kind === "svc" ? ` data-i="${n.i}"` : ""}>` +
         `<rect x="${n.x}" y="${n.y}" width="${BW}" height="20" rx="5" stroke="${color}"/>` +
         `<text x="${n.x + 7}" y="${n.y + 14}">${esc(txt)}</text><title>${esc(n.label)}</title></g>`;
  });
  el.innerHTML = s + "</svg>";
  const svg = el.querySelector("svg");
  const focus = (svc) => {
    svg.classList.toggle("focus", !!svc);
    svg.querySelectorAll("[data-svcs]").forEach((g) =>
      g.classList.toggle("hl", !!svc && g.dataset.svcs.split(" ").includes(svc)));
  };
  svg.querySelectorAll("g.svc").forEach((g) => {
    const svc = t.results[+g.dataset.i].service;
    g.addEventListener("mouseenter", () => focus(svc));
    g.addEventListener("mouseleave", () => focus(t.results[state.selected].service));
    g.addEventListener("click", () => select(+g.dataset.i));
  });
  focus(t.results[state.selected].service);
}

/* ---------- ranked list + detail ---------- */
function select(i) {
  state.selected = i; renderRanked(); renderDetail();
  const t = state.triage, svc = t.results[i].service, svg = document.querySelector("#map svg");
  if (svg) { svg.classList.add("focus"); svg.querySelectorAll("[data-svcs]").forEach((g) =>
    g.classList.toggle("hl", g.dataset.svcs.split(" ").includes(svc))); }
}

function renderRanked() {
  const t = state.triage, el = $("ranked");
  if (!t || !t.known_cve) { el.innerHTML = `<p class="hint">${esc((t && t.summary) || "Run triage.")}</p>`; return; }
  const max = Math.max(...t.results.map((r) => r.risk));
  el.innerHTML = t.results.map((r, i) =>
    `<div class="row${i === state.selected ? " sel" : ""}" data-i="${i}" tabindex="0">` +
    `<span class="pill ${r.verdict}">${r.verdict}</span>` +
    `<span class="mono">${r.risk.toFixed(1)}</span>` +
    `<span class="riskbar"><i style="width:${(100 * r.risk / max).toFixed(0)}%"></i></span>` +
    `<span class="svcname">${esc(r.service)}</span>` +
    `<span class="tags">${state.changed && state.changed[r.service] ? `<span class="tag chg">${esc(state.changed[r.service])}</span>` : ""}` +
    `${r.reachable ? `<span class="tag pub" title="reachable from a public endpoint">public</span>` : ""}` +
    `<span class="tag">${esc(r.tier)}</span></span></div>`).join("");
  el.querySelectorAll(".row").forEach((d) => {
    d.addEventListener("click", () => select(+d.dataset.i));
    d.addEventListener("keydown", (e) => { if (e.key === "Enter") select(+d.dataset.i); });
  });
}

function chain(nodes, edges, target) {
  return nodes.map((n, i) => {
    const lab = label0(n), isT = lab === "Service" && n.properties.name === target;
    const edge = i < edges.length ? `<div class="hop">${esc(edges[i].type)}</div>` : "";
    return `<div class="cnode${isT ? " target" : ""}" style="--c:${COLORS[lab] || "#8b949e"}">` +
      `<span class="lab">${esc(lab)}</span> ${esc(shortLabel(n))}<span class="nid">#${n.id}</span></div>${edge}`;
  }).join("");
}

function renderDetail() {
  const t = state.triage, el = $("detail");
  if (!t || !t.known_cve || !t.results.length) { el.innerHTML = "<p class='hint'>Select a service.</p>"; return; }
  const r = t.results[state.selected], c = r.components, ex = r.exposure;
  const ok = (v) => v ? `<span class="okmark">verified ✓</span>` : `<span class="badmark">FAILED ✗</span>`;
  const route = ex && ex.path
    ? `<div class="seg"><div class="seghead">1 · public route ${ok(ex.verified)} <span class="kv">${esc(ex.detail)}</span></div>` +
      chain(ex.path.nodes, ex.path.edges, r.service) + `<div class="hop">USES</div></div>`
    : `<div class="seg"><div class="seghead">1 · public route <span class="kv">none: no public endpoint reaches ${esc(r.service)} within 4 calls</span></div></div>`;
  const dep = r.proof.path;
  const depNodes = ex && ex.path ? dep.nodes.slice(1) : dep.nodes;
  const depEdges = ex && ex.path ? dep.edges.slice(1) : dep.edges;
  el.innerHTML =
    `<p><span class="pill ${r.verdict}">${r.verdict}</span> <b>${esc(r.service)}</b> ` +
    `<span class="kv">owner <b>${esc(r.owner.team)}</b> ${esc(r.owner.slack_channel)} · last deploy ${esc(r.owner.last_deployer)}</span></p>` +
    `<p class="kv">risk <b>${r.risk.toFixed(2)}</b> = severity ${c.severity} × exposure ${c.exposure} × criticality ${c.criticality}` +
    ` · rules <b>${r.rules_fired.map(esc).join(", ")}</b> → ${esc(r.verdict_reason)}</p>` +
    (r.centrality ? `<p class="kv">call graph (FalkorDB algo.pageRank / algo.betweenness): PageRank <b>#${r.centrality.rank}</b> of ${r.centrality.of} ` +
      `(${r.centrality.pagerank}) · betweenness <b>${r.centrality.betweenness.toFixed(1)}</b> · called by ${r.centrality.in_degree}, calls ${r.centrality.out_degree}</p>` : "") +
    `<p class="explain">${esc(r.explanation)}</p>` +
    `<div class="chain">${route}` +
    `<div class="seg"><div class="seghead">2 · dependency chain ${ok(r.proof.verified)} <span class="kv">${esc(r.proof.detail)}</span></div>` +
    chain(depNodes, depEdges, r.service) +
    `<div class="hop">AFFECTED BY</div><div class="cnode" style="--c:${COLORS.CVE}"><span class="lab">CVE</span> ${esc(t.cve.id)} ` +
    `<span class="kv">cvss ${t.cve.cvss}${t.cve.in_kev ? " · KEV" : ""}</span></div></div></div>`;
}

/* ---------- Claude investigation (SSE) ---------- */
let es = null;
function renderFindings(out) {
  const el = $("findings");
  if (!out.findings.length) { el.innerHTML = `<div class="refuse">No findings submitted (${esc(out.stop)}). ${esc(out.summary)}</div>`; return; }
  const approvable = out.findings.filter((f) => f.verdict === "ACT_NOW" && f.verdict_agrees && f.proof.verified);
  state.findings = approvable.map((f) => f.service);
  el.innerHTML = `<div class="ok"><b>Claude:</b> ${esc(out.summary)} ` +
    `<span class="kv">${out.trace.length} tool calls · ${(out.total_latency_ms / 1000).toFixed(1)}s · stop: ${esc(out.stop)}</span></div>` +
    `<table class="ftable"><tr><th>service</th><th>Claude's verdict</th><th>rules agree?</th><th>proof in graph</th><th>reason</th></tr>` +
    out.findings.map((f) => `<tr><td>${esc(f.service)}</td><td><span class="pill ${f.verdict}">${f.verdict}</span></td>` +
      `<td>${f.verdict_agrees ? `<span class="okmark">✓ agrees</span>` : `<span class="badmark">✗ rules say ${esc(f.rule_verdict || "nothing (not evaluated)")}</span>`}</td>` +
      `<td>${f.proof.verified ? `<span class="okmark">✓</span>` : `<span class="badmark" title="${esc(f.proof.detail)}">✗ ${esc(f.proof.detail)}</span>`}</td>` +
      `<td class="kv">${esc(f.reason)}</td></tr>`).join("") + `</table>` +
    `<div class="controls"><button id="approveBtn" ${approvable.length ? "" : "disabled"}>` +
    `Approve: ticket + notify ${approvable.length} verified ACT_NOW finding${approvable.length === 1 ? "" : "s"}</button>` +
    `<span class="kv">only findings whose verdict matches the rules and whose proof verified; the guardrail re-checks each action</span></div>`;
  $("approveBtn").addEventListener("click", async () => {
    const out2 = await post("/api/act", { cve: cve(), org: org(), verdicts: ["ACT_NOW"], services: state.findings });
    renderActed(out2); refreshDecisions(); refreshLog();
    $("approveBtn").disabled = true;
  });
}

function investigate() {
  if (es) es.close();
  $("trace").innerHTML = ""; $("findings").innerHTML = ""; $("agentNote").textContent = "";
  const q = $("question").value.trim();
  const url = `/api/investigate?org=${org()}&cve=${encodeURIComponent(cve())}&question=${encodeURIComponent(q)}`;
  $("askBtn").disabled = true; $("askBtn").textContent = "Investigating…";
  const done = () => { es.close(); es = null; $("askBtn").disabled = false; $("askBtn").textContent = "Investigate"; };
  es = new EventSource(url);
  es.onmessage = (m) => {
    const e = JSON.parse(m.data), li = document.createElement("li");
    if (e.type === "start") {
      $("agentNote").textContent = `Claude discovered ${e.tools_offered.length} tools over MCP: ${e.tools_offered.join(", ")}`;
      return;
    }
    if (e.type === "text") { li.className = "say"; li.textContent = e.text; }
    else if (e.type === "step") {
      li.className = e.is_error ? "err" : "";
      const args = Object.entries(e.args).filter(([k]) => k !== "org").map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(", ");
      li.innerHTML = `<span class="stepn">${e.step}</span><b class="mono">${esc(e.tool)}</b><span class="mono kv">(${esc(args)})</span>` +
        `${e.latency_ms != null ? ` <span class="kv">${e.latency_ms}ms</span>` : ""}` +
        `<div class="why">why: ${esc(e.reason || "(no reason given)")}</div>` +
        (e.brief ? `<div class="got">→ ${esc(e.brief)}</div>` : "");
    } else if (e.type === "done") { renderFindings(e); done(); return; }
    else if (e.type === "error") { $("findings").innerHTML = `<div class="refuse">${esc(e.error)}</div>`; done(); return; }
    $("trace").appendChild(li);
  };
  es.onerror = () => { if (es) { $("findings").innerHTML ||= `<div class="refuse">stream closed</div>`; done(); } };
}

/* ---------- live change: mutate the graph, re-triage, diff ---------- */
function fillLiveSvc() {
  const t = state.triage, sel = $("liveSvc"), op = $("liveOp").value;
  const tierRank = { critical: 0, standard: 1, internal: 2 };
  let opts = [];
  if (t && t.known_cve) {
    const affected = new Set(t.results.map((r) => r.service));
    const vRank = { ACT_NOW: 0, SCHEDULE: 1, SUPPRESS: 2 };
    opts = op === "expose"
      ? t.results.filter((r) => !r.reachable).map((r) => ({ name: r.service, tier: r.tier, note: r.verdict }))
      : op === "pin"
      ? (t.cve.fixed_purl ? t.results.map((r) => ({ name: r.service, tier: r.tier, note: r.verdict })) : [])
      : state.services.filter((s) => !affected.has(s.name)).map((s) => ({ ...s, note: "not affected" }));
    opts.sort((a, b) => (op === "pin" ? vRank[a.note] - vRank[b.note] : 0)
      || tierRank[a.tier] - tierRank[b.tier] || a.name.localeCompare(b.name));
  }
  const none = { expose: "every affected service is already reachable", adopt: "no unaffected services",
                 pin: "no fixed version in the graph" }[op];
  sel.innerHTML = opts.length ? opts.map((o) => `<option value="${esc(o.name)}">${esc(o.name)} · ${esc(o.tier)} · ${esc(o.note)}</option>`).join("")
    : `<option value="">${none}</option>`;
  $("assessBtn").disabled = !opts.length;
  $("liveBtn").disabled = !opts.length || op === "pin";
  $("liveBtn").title = op === "pin" ? "upgrades are simulated org-wide under Fix simulation; this checks one service's PR" : "";
}

function liveRequest() {
  const t = state.triage, svc = $("liveSvc").value, op = $("liveOp").value;
  return op === "expose" ? { service: svc, expose: `/live/${svc}` }
    : op === "pin" ? { service: svc, adds: [t.cve.fixed_purl], removes: [t.cve.vuln_purl] }
    : { service: svc, adds: [t.cve.vuln_purl] };
}

async function assessLive() {
  $("assessBtn").disabled = true;
  $("liveDiff").innerHTML = "<p class='hint'>copying the graph into a sandbox, applying the change there, re-scoring every CVE…</p>";
  try {
    const r = await post("/api/assess", { ...liveRequest(), org: org() });
    const pill = (v) => v ? `<span class="pill ${v}">${v}</span>` : `<span class="kv">not affected</span>`;
    $("liveDiff").innerHTML = `<div class="diff"><b>Sandbox prediction</b> <span class="kv">${r.cves_checked} CVEs re-scored in a copy of the graph · ` +
      `${r.latency_ms.toFixed(0)}ms · live graph untouched · ${r.worst === "ACT_NOW" ? "a pre-merge gate would <b>fail</b> this change" : "a pre-merge gate would pass this change"}</span>` +
      (r.findings.length ? r.findings.map((f) => `<div><b class="mono">${esc(f.cve)}</b> <b>${esc(f.service)}</b> ${pill(f.before)} → ${pill(f.after)} ` +
        `<span class="kv">${f.reachable ? `public via ${esc(f.entry_point)}` : "no public path"} · ${f.chain.map((x) => esc(x.split("/").pop())).join(" → ")}</span></div>`).join("")
        : `<div class="kv">no verdict gets worse</div>`) +
      (r.resolved || []).map((f) => `<div><b class="mono">${esc(f.cve)}</b> <b>${esc(f.service)}</b> ${pill(f.before)} → ${pill(f.after)} ` +
        `<span class="okmark">resolved by this change ✓</span> <span class="kv">${f.after ? "" : "no dependency path left that avoids the removed version"}</span></div>`).join("") + `</div>`;
  } catch (e) { $("liveDiff").innerHTML = `<div class="refuse">${esc(e.message)}</div>`; }
  $("assessBtn").disabled = false;
}

async function refreshLive() {
  try {
    const { changes } = await api(`/api/live?org=${org()}`);
    $("liveChanges").innerHTML = changes.length
      ? `<p class="kv">live changes in this graph: ` + changes.map((c) =>
          c.kind === "expose" ? `<b>${esc(c.what)}</b> → ${esc(c.service)}` : `<b>${esc(c.service)}</b> uses ${esc(c.what.split("/").pop())}`).join(" · ") + `</p>`
      : "";
    $("revertBtn").disabled = !changes.length;
  } catch (e) { $("liveChanges").innerHTML = `<p class="hint">${esc(e.message)}</p>`; }
}

function diffTriage(before, after, what) {
  if (!before || !before.known_cve || !after.known_cve) { $("liveDiff").innerHTML = `<div class="diff">${esc(what)}</div>`; return; }
  const b = new Map(before.results.map((r) => [r.service, r])), a = new Map(after.results.map((r) => [r.service, r]));
  const lines = [], changed = {};
  const pill = (v) => `<span class="pill ${v}">${v}</span>`;
  a.forEach((r, svc) => {
    const o = b.get(svc);
    if (!o) { changed[svc] = "new"; lines.push(`<b>${esc(svc)}</b> joined the blast radius ${pill(r.verdict)} <span class="kv">${esc(r.proof.detail)}</span>`); return; }
    const parts = [];
    if (o.verdict !== r.verdict) { parts.push(`${pill(o.verdict)} → ${pill(r.verdict)}`); changed[svc] = `was ${o.verdict}`; }
    if (o.reachable !== r.reachable) parts.push(r.reachable
      ? `now reachable via <span class="mono">${esc(r.exposure.path.nodes[0].properties.path)}</span> ${r.exposure.verified ? `<span class="okmark">route verified ✓</span>` : ""}`
      : "no longer reachable");
    if (parts.length) { changed[svc] ||= "changed"; lines.push(`<b>${esc(svc)}</b> ${parts.join(" · ")}`); }
  });
  b.forEach((o, svc) => { if (!a.has(svc)) lines.push(`<b>${esc(svc)}</b> left the blast radius`); });
  state.changed = changed;
  const n = (t, v) => t.results.filter((r) => r.verdict === v).length;
  $("liveDiff").innerHTML = `<div class="diff"><b>${esc(what)}</b> <span class="kv">re-triaged in ${after.total_latency_ms}ms · ` +
    `affected ${before.results.length} → ${after.results.length} · ACT_NOW ${n(before, "ACT_NOW")} → ${n(after, "ACT_NOW")}</span>` +
    (lines.length ? lines.map((l) => `<div>${l}</div>`).join("") : `<div class="kv">no verdict changed</div>`) + `</div>`;
  const first = after.results.findIndex((r) => changed[r.service]);
  if (first >= 0) select(first);
}

async function liveChange(req, label) {
  const before = state.triage;
  $("liveBtn").disabled = $("assessBtn").disabled = $("revertBtn").disabled = true;
  try {
    const out = await post(req.path, req.body);
    await runTriage(true);
    diffTriage(before, state.triage, label(out));
  } catch (e) { $("liveDiff").innerHTML = `<div class="refuse">${esc(e.message)}</div>`; }
  refreshLive(); fillLiveSvc();
}

/* ---------- simulation, actions, decisions, log ---------- */
function renderSim() {
  const c = state.compare, el = $("sim");
  if (!c) { el.innerHTML = ""; return; }
  const max = Math.max(...c.candidates.map((x) => x.before.total_risk));
  el.innerHTML = c.candidates.map((x) =>
    `<div class="simrow"><b class="mono">${esc(x.cve)}</b> <span class="kv">upgrade ${esc(x.fix.split("@")[0].split("/").pop())} → ${esc((x.successor || "").split("@").pop())}</span>` +
    `<div class="bar"><i style="width:${(100 * x.before.total_risk / max).toFixed(1)}%"></i>` +
    `<u style="width:${(100 * x.after.total_risk / max).toFixed(1)}%"></u></div>` +
    `<span class="kv">org risk ${x.before.total_risk.toFixed(1)} → <b>${x.after.total_risk.toFixed(1)}</b> (−${x.risk_reduction.toFixed(1)}) · reachable ${x.before.reachable} → ${x.after.reachable}</span></div>`
  ).join("") + `<div class="rec">RECOMMEND <b>${esc(c.recommendation.cve)}</b>: ${esc(c.recommendation.reason)}</div>`;
}

function renderActed(out) {
  $("acted").innerHTML = `<div class="ok">${esc(out.summary)}</div>` +
    out.actions.map((a) => `<div class="loge">+ [${esc(a.kind)}] ${esc(a.service)} → ${esc(a.decision_id || "")} <span class="kv">(${esc(a.mode || "")})</span></div>`).join("") +
    out.refusals.map((r) => `<div class="refuse">! [${esc(r.kind)}] ${esc(r.service)}: ${esc(r.reason)}</div>`).join("");
}

async function refreshDecisions() {
  try {
    const ds = (await api(`/api/decisions?org=${org()}`)).decisions.filter((d) => d.cve === cve());
    $("decisions").innerHTML = ds.length ? ds.slice(0, 12).map((d) =>
      `<div class="loge"><span class="pill ${d.verdict}">${esc(d.verdict)}</span> <b>${esc(d.action)}</b> ${esc(d.service)} ` +
      `<span class="kv">FIRED ${esc((d.rules || []).join(", "))} · ${new Date(d.ts * 1000).toLocaleTimeString()}</span></div>`).join("") +
      (ds.length > 12 ? `<p class="kv">+${ds.length - 12} more</p>` : "")
      : "<p class='hint'>None for this CVE yet.</p>";
  } catch (e) { $("decisions").innerHTML = `<p class="hint">${esc(e.message)}</p>`; }
}

function renderLog(entries) {
  const el = $("alog"), only = $("logThisCve").checked;
  entries = entries.filter((e) => (e.org || "dev") === org() && (!only || e.cve === cve()));
  if (!entries.length) { el.innerHTML = "<p class='hint'>No entries yet.</p>"; return; }
  const shown = entries.slice(-25).reverse();
  el.innerHTML = shown.map((e) =>
    `<div class="loge"><span class="pill ${e.accepted ? "SUPPRESS" : "ACT_NOW"}">${e.accepted ? "accept" : "refuse"}</span> ` +
    `<b>${esc(e.action)}</b> ${esc(e.cve)} / ${esc(e.service)} ` +
    `<span class="kv">${esc(e.accepted ? (e.decision_id || e.mode || "") : (e.reason || ""))}</span></div>`).join("") +
    (entries.length > shown.length ? `<p class="kv">showing latest ${shown.length} of ${entries.length}</p>` : "");
}

async function refreshLog() {
  try { renderLog((await api("/api/action_log?n=500")).entries); }
  catch (e) { $("alog").innerHTML = `<p class="hint">log error: ${esc(e.message)}</p>`; }
}

/* ---------- wiring ---------- */
async function loadCves() {
  try {
    const { cves } = await api(`/api/cves?org=${org()}`);
    $("cveList").innerHTML = cves.map((c) =>
      `<option value="${esc(c.id)}">cvss ${c.cvss}${c.in_kev ? " · KEV" : ""} · ${esc(c.summary)}</option>`).join("");
  } catch (e) { /* free text still works */ }
}

async function runTriage(keepDiff = false) {
  $("status").textContent = "triaging…";
  try {
    state.triage = await api(`/api/triage?cve=${encodeURIComponent(cve())}&org=${org()}`);
    state.selected = 0; state.compare = null;
    if (!keepDiff) { state.changed = null; $("liveDiff").innerHTML = ""; }
    fillLiveSvc();
    renderSummary(); renderMap(); renderRanked(); renderDetail(); renderSim();
    for (const b of ["simBtn", "actBtn", "drillBtn"]) $(b).disabled = !state.triage.known_cve;
    $("acted").innerHTML = ""; $("refusal").innerHTML = "";
    refreshDecisions(); refreshLog();
    $("status").textContent = "";
  } catch (e) { $("status").textContent = `error: ${e.message}`; }
}

async function loadServices() {
  try { state.services = (await api(`/api/services?org=${org()}`)).services; } catch (e) { state.services = []; }
  fillLiveSvc(); refreshLive();
}

$("triageBtn").addEventListener("click", () => runTriage());
$("cve").addEventListener("keydown", (e) => { if (e.key === "Enter") runTriage(); });
$("org").addEventListener("change", () => { loadCves(); loadServices(); runTriage(); });
$("liveOp").addEventListener("change", fillLiveSvc);
$("assessBtn").addEventListener("click", assessLive);
$("liveBtn").addEventListener("click", () => liveChange(
  { path: "/api/live", body: { op: $("liveOp").value, service: $("liveSvc").value, cve: cve(), org: org() } },
  (out) => out.summary));
$("revertBtn").addEventListener("click", () => liveChange(
  { path: "/api/live_revert", body: { org: org() } },
  (out) => `reverted ${out.endpoints} endpoint(s), ${out.dependencies} dependency edge(s)`));
$("askBtn").addEventListener("click", investigate);
$("question").addEventListener("keydown", (e) => { if (e.key === "Enter") investigate(); });

$("simBtn").addEventListener("click", async () => {
  $("sim").innerHTML = "<p class='hint'>simulating each fix in a sandbox graph copy…</p>";
  try { state.compare = await api(`/api/compare?cve=${encodeURIComponent(cve())}&org=${org()}`); renderSim(); }
  catch (e) { $("sim").innerHTML = `<p class="hint">error: ${esc(e.message)}</p>`; }
});

$("actBtn").addEventListener("click", async () => {
  renderActed(await post("/api/act", { cve: cve(), org: org(), verdicts: ["ACT_NOW"] }));
  refreshDecisions(); refreshLog();
});

$("drillBtn").addEventListener("click", async () => {
  const out = await post("/api/refusal_drill", { cve: cve(), org: org() });
  $("refusal").innerHTML = out.accepted
    ? `<div class="refuse">DRILL PROBLEM: forged proof was accepted!</div>`
    : `<div class="refuse"><b>Guardrail refused the forged proof</b> (drill: ${esc(out.drill)}, ${esc(out.service)})<br>${esc(out.reason)}</div>`;
  refreshLog();
});

$("logBtn").addEventListener("click", refreshLog);
$("logThisCve").addEventListener("change", refreshLog);
window.addEventListener("resize", () => { if (state.triage) renderMap(); });

(async () => {
  try {
    state.config = await api("/api/config");
    const w = (on, txt) => `<span class="wire ${on ? "on" : ""}">${txt}</span>`;
    $("wires").innerHTML = w(state.config.agent_llm, state.config.agent_llm ? `Claude: ${esc(state.config.model)}` : "Claude: no API key") +
      w(state.config.github_live, state.config.github_live ? "GitHub: live" : "GitHub: dry-run") +
      w(state.config.slack_live, state.config.slack_live ? "Slack: live" : "Slack: dry-run");
    if (!state.config.agent_llm) {
      $("askBtn").disabled = true;
      $("agentNote").innerHTML = "Set <span class='mono'>ANTHROPIC_API_KEY</span> in <span class='mono'>.env</span> and restart the UI to let Claude investigate. Everything else on this page runs without it.";
    }
  } catch (e) { /* non-fatal */ }
  loadCves();
  loadServices();
  runTriage();
})();
