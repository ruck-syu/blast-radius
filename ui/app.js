/* Blast Radius UI: ranked list, SVG proof paths, simulation, actions, log. No deps. */
const $ = (id) => document.getElementById(id);
const state = { triage: null, selected: 0, compare: null };

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function shortLabel(n) {
  const p = n.properties || {};
  const lab = (n.labels || ["?"])[0];
  if (lab === "Package") { const v = (p.purl || "").split("@")[0].split("/").pop(); return `${p.name}@${p.version} (${v})`; }
  return p.name || p.path || p.id || p.handle || "?";
}
const COLORS = { Service:"#1f6feb", Package:"#9e6a03", CVE:"#da3633", Endpoint:"#1a7f37",
  Team:"#6e7681", Person:"#6e7681", Deployment:"#6e7681", Rule:"#6e7681", Decision:"#6e7681" };

function renderPath(path) {
  if (!path || !path.nodes) return "<p class='hint'>No path.</p>";
  const W = 640, bh = 40, gap = 34, colors = COLORS;
  const H = path.nodes.length * (bh + gap);
  let s = `<svg class="path" viewBox="0 0 ${W} ${H}" style="height:${Math.min(H, 560)}px">`;
  path.nodes.forEach((n, i) => {
    const y = i * (bh + gap), lab = (n.labels || ["?"])[0];
    const c = colors[lab] || "#6e7681";
    if (i > 0) {
      const et = (path.edges[i - 1] || {}).type || "?";
      s += `<line x1="${W/2}" y1="${y - gap}" x2="${W/2}" y2="${y}" stroke="#8b949e"/>` +
           `<text x="${W/2 + 8}" y="${y - gap/2 + 4}" fill="#8b949e" font-size="11">${esc(et)}</text>`;
    }
    s += `<rect x="40" y="${y}" width="${W-80}" height="${bh}" rx="6" fill="#161b22" stroke="${c}" stroke-width="2"/>` +
         `<text x="52" y="${y + 17}" fill="#e6edf3" font-size="12">${esc(lab)}: ${esc(shortLabel(n))}</text>` +
         `<text x="52" y="${y + 32}" fill="#8b949e" font-size="10">id ${n.id}</text>`;
  });
  return s + "</svg>";
}

function renderRanked() {
  const t = state.triage;
  const el = $("ranked");
  if (!t || !t.known_cve) { el.innerHTML = `<p class="hint">${esc((t && t.summary) || "Run triage.")}</p>`; return; }
  const max = Math.max(...t.results.map((r) => r.risk));
  el.innerHTML = t.results.map((r, i) =>
    `<div class="row${i === state.selected ? " sel" : ""}" data-i="${i}">` +
    `<span class="pill ${r.verdict}">${r.verdict}</span>` +
    `<span class="mono">${r.risk.toFixed(1)}</span>` +
    `<span class="riskbar"><i style="width:${(100 * r.risk / max).toFixed(0)}%"></i></span>` +
    `<span>${esc(r.service)}${r.reachable ? " 🌐" : ""}</span></div>`).join("");
  el.querySelectorAll(".row").forEach((d) =>
    d.addEventListener("click", () => { state.selected = +d.dataset.i; renderRanked(); renderDetail(); }));
}

function renderDetail() {
  const t = state.triage, el = $("detail");
  if (!t || !t.known_cve || !t.results.length) { el.innerHTML = "<p class='hint'>Select a service.</p>"; return; }
  const r = t.results[state.selected];
  el.innerHTML =
    `<p><span class="pill ${r.verdict}">${r.verdict}</span> <b>${esc(r.service)}</b> ` +
    `<span class="kv">risk <b>${r.risk.toFixed(2)}</b> = ${r.components.severity}×${r.components.exposure}×${r.components.criticality} · depth ${r.depth} · ${r.reachable ? "reachable 🌐" : "no public path"}</span></p>` +
    `<p class="kv">rules: <b>${r.rules_fired.map(esc).join(", ")}</b> — ${esc(r.verdict_reason)}</p>` +
    `<p class="kv">owner: <b>${esc(r.owner.team)}</b> (${esc(r.owner.slack_channel)}), last deploy ${esc(r.owner.last_deployer)}</p>` +
    `<p>${esc(r.explanation)}</p>` +
    `<p class="kv">proof ${r.proof.verified ? "verified ✓" : "FAILED ✗"} — ${esc(r.proof.detail)}</p>` +
    renderPath(r.proof.path);
}

function renderSummary() {
  const t = state.triage, el = $("summary");
  if (!t) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  const cid = (t.cve && t.cve.id) || t.cve || "";
  el.innerHTML = `<b>${esc(cid)}</b> — ${esc(t.summary)} ` +
    `<span class="kv">(${t.plan ? t.plan.length : 0} tool calls, ${t.total_latency_ms}ms)</span>`;
}

function renderSim() {
  const c = state.compare, el = $("sim");
  if (!c) { el.innerHTML = ""; return; }
  const max = Math.max(...c.candidates.map((x) => x.before.total_risk));
  el.innerHTML = c.candidates.map((x) =>
    `<div><b class="mono">${esc(x.cve)}</b> <span class="kv">upgrade ${esc(x.fix.split("@")[0])} → ${esc((x.successor || "").split("@").pop())}</span>` +
    `<div class="bar"><i style="width:${(100 * x.before.total_risk / max).toFixed(1)}%"></i>` +
    `<u style="width:${(100 * x.after.total_risk / max).toFixed(1)}%"></u></div>` +
    `<span class="kv">risk ${x.before.total_risk.toFixed(1)} → ${x.after.total_risk.toFixed(1)} (−${x.risk_reduction.toFixed(1)}), reachable ${x.before.reachable} → ${x.after.reachable}</span></div>`
  ).join("") + `<div class="rec">RECOMMEND <b>${esc(c.recommendation.cve)}</b>: ${esc(c.recommendation.reason)}</div>`;
}

function renderLog(entries) {
  const el = $("alog");
  if (!entries.length) { el.innerHTML = "<p class='hint'>No entries yet.</p>"; return; }
  el.innerHTML = entries.slice().reverse().map((e) =>
    `<div class="loge"><span class="pill ${e.accepted ? "SUPPRESS" : "ACT_NOW"}">${e.accepted ? "accept" : "refuse"}</span> ` +
    `<b>${esc(e.action)}</b> ${esc(e.cve)} / ${esc(e.service)} ` +
    `<span class="kv">${esc(e.accepted ? (e.decision_id || e.mode || "") : (e.reason || ""))}</span></div>`).join("");
}

async function refreshLog() {
  try { renderLog((await api("/api/action_log?n=100")).entries); }
  catch (e) { $("alog").innerHTML = `<p class="hint">log error: ${esc(e.message)}</p>`; }
}

$("triageBtn").addEventListener("click", async () => {
  const cve = $("cve").value.trim(), org = $("org").value;
  $("status").textContent = "triaging…";
  try {
    state.triage = await api(`/api/triage?cve=${encodeURIComponent(cve)}&org=${org}`);
    state.selected = 0; state.compare = null;
    renderSummary(); renderRanked(); renderDetail(); renderSim();
    $("simBtn").disabled = !state.triage.known_cve;
    $("actBtn").disabled = !state.triage.known_cve;
    $("drillBtn").disabled = !state.triage.known_cve;
  } catch (e) { $("status").textContent = `error: ${e.message}`; return; }
  $("status").textContent = "";
});

$("simBtn").addEventListener("click", async () => {
  $("sim").innerHTML = "<p class='hint'>simulating…</p>";
  state.compare = await api(`/api/compare?cve=${encodeURIComponent($("cve").value.trim())}&org=${$("org").value}`);
  renderSim();
});

$("actBtn").addEventListener("click", async () => {
  const out = await api("/api/act", { method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ cve: $("cve").value.trim(), org: $("org").value, verdicts: ["ACT_NOW"] }) });
  $("acted").innerHTML = `<div class="ok">${esc(out.summary)}</div>` +
    out.actions.map((a) => `<div class="loge">+ [${esc(a.kind)}] ${esc(a.service)} → ${esc(a.decision_id || "")} (${esc(a.mode || "")})</div>`).join("") +
    out.refusals.map((r) => `<div class="refuse">! [${esc(r.kind)}] ${esc(r.service)}: ${esc(r.reason)}</div>`).join("");
  refreshLog();
});

$("drillBtn").addEventListener("click", async () => {
  const out = await api("/api/refusal_drill", { method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ cve: $("cve").value.trim(), org: $("org").value }) });
  $("refusal").innerHTML = out.accepted
    ? `<div class="refuse">DRILL PROBLEM: forged proof was accepted!</div>`
    : `<div class="refuse"><b>Guardrail refusal (drill: ${esc(out.drill)})</b><br>${esc(out.reason)}</div>`;
  refreshLog();
});

$("logBtn").addEventListener("click", refreshLog);
refreshLog();
