/* jev-vulnops dashboard: sidebar, dense triage table, detail pane, API playground.
   Jev answers; this file only does arithmetic and rendering -- routing lives in
   routing.js, a mirror of the Python gate. */

const state = {
  vulns: [],
  questions: [],
  meta: { price: 0.042, questions: 3 },
  results: {}, // cve_id -> decision payload from /api/triage/stream
  feed: {}, // cve_id -> { status, d?, error? }
  order: [], // arrival order
  filter: "all",
  search: "",
  sort: "escalated",
  pgSetId: null,
  selected: null,
  source: null,
  timer: null,
  running: false,
  threshold: 0.75,
  flipped: null, // cve_ids whose routing flipped on the last gate drag
  runTotal: 0,
  runDone: 0,
  runStartedAt: 0,
};

const $ = (id) => document.getElementById(id);

/* ---------------- palette ---------------- */

const ACTION_COLORS = {
  "remediate-now": "#f87171",   // red — urgent
  "sla-remediate": "#fbbf24",   // amber — scheduled
  "accept-risk": "#34d399",     // green — accepted
  "needs-intel": "#818cf8",     // indigo — investigate
};
const LEVEL_COLORS = ["#4ade80", "#facc15", "#fb923c", "#f87171"]; // low→critical
const ACCENT = "#6366f1";

function barColor(label, idx, total, kind, isWinner) {
  if (kind === "choice") return ACTION_COLORS[label] || (isWinner ? "#34d399" : ACCENT);
  if (kind === "score") return LEVEL_COLORS[Math.round(idx * (LEVEL_COLORS.length - 1) / Math.max(total - 1, 1))];
  if (kind === "noul") return label === "yes" ? "#fbbf24" : "#34d399";
  return isWinner ? "#34d399" : ACCENT;
}
function confColor(c) { return c >= 0.75 ? "#34d399" : c >= 0.5 ? "#fbbf24" : "#f87171"; }
function levelColor(position) { return LEVEL_COLORS[Math.min(3, Math.floor(position * 4))]; }

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function sevClass(cvss) {
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
}
function fmt(n, digits = 2) { return Number(n).toFixed(digits); }
function fmtMs(n) { return n ? `${Math.round(n)} ms` : "—"; }
function fmtTok(n) { return n >= 1000 ? (n / 1000).toFixed(1) + "k" : String(Math.round(n)); }

function typeChip(t) { return `<span class="chip-type t-${t}">${t}</span>`; }

// Legend values may be plain names or criteria objects ({name, description}).
function legendName(v, fallback) {
  if (v == null) return fallback;
  if (typeof v === "object") return v.name ?? fallback;
  return String(v);
}

// Index-keyed probabilities (score) -> legend-labeled, order-preserving map.
function labelScoreProbs(probabilities, legend) {
  const out = {};
  const keys = Object.keys(probabilities || {}).sort((a, b) => Number(a) - Number(b));
  for (const k of keys) out[legendName((legend || {})[k], k)] = probabilities[k];
  return out;
}

/* ---------------- derived numbers (code decides, never the model) ---------------- */

function route(d) {
  return routeOf(d, state.threshold);
}
function tokensOf(d) {
  const used = Number(d.detail?.usage?.input_tokens);
  return Number.isFinite(used) && used > 0 ? used : Number(d.input_tokens || 0);
}
function costOf(d) {
  const billed = Number(d.detail?.usage?.cost); // OpenRouter reports cost; direct route does not
  if (Number.isFinite(billed) && billed > 0) return billed;
  return (tokensOf(d) / 1e6) * (state.meta.price || 0);
}
function vulnOf(cveId) {
  return state.vulns.find((x) => x.cve_id === cveId);
}

/* ---------------- bars ---------------- */

function barTrack(value, color, gate) {
  const w = Math.max(0, Math.min(1, Number(value) || 0)) * 100;
  const tick = gate == null ? "" : `<i class="gate" style="left:${(gate * 100).toFixed(1)}%"></i>`;
  return `<span class="bar-track"><span class="bar-fill" style="width:${w.toFixed(1)}%; background:${color}"></span>${tick}</span>`;
}

function barRow(label, value, color, opts) {
  const o = opts || {};
  const spread = o.spread ? `<span class="spread">±${fmt(o.spread)}</span>` : "";
  return `<div class="bar-row"><span class="label">${esc(label)}</span>${barTrack(value, color, o.gate)}<span class="val">${fmt(value)}${spread}</span></div>`;
}

// One probability distribution as horizontal bars. `gate` draws the routing tick.
// Score levels stay in rubric order (low→critical) so the ramp reads as a shape;
// choice/noul sort by probability so the answer is the top row.
function bars(probabilities, winner, kind, opts) {
  const o = opts || {};
  const entries = Object.entries(probabilities || {}).map(([k, p], i) => ({ k, p, i }));
  if (kind !== "score") entries.sort((a, b) => b.p - a.p);
  const total = entries.length;
  const rows = entries
    .map(({ k, p, i }) => {
      const isWinner = String(k) === String(winner);
      return barRow(k, p, barColor(k, i, total, kind, isWinner), { gate: o.gate, spread: o.spreads?.[k] });
    })
    .join("");
  return `<div class="bars">${rows}</div>`;
}

function mbar(value, color, gate, title) {
  return `<div class="mbar" title="${esc(title)}">${barTrack(value, color, gate)}<span class="mv">${fmt(value)}</span></div>`;
}

function payloadDetails(request, response) {
  return `
    <details class="payload">
      <summary>▸ request / response payloads</summary>
      <h4>request</h4>
      <pre>${esc(JSON.stringify(request, null, 2))}</pre>
      <h4>response</h4>
      <pre>${esc(JSON.stringify(response, null, 2))}</pre>
    </details>`;
}

/* ---------------- sidebar ---------------- */

function matchesSearch(v) {
  const q = state.search.toLowerCase();
  return !q || v.cve_id.toLowerCase().includes(q) || v.asset.name.toLowerCase().includes(q);
}

function renderList() {
  const ul = $("vulnList");
  ul.innerHTML = "";
  let counts = { all: 0, AUTO: 0, ESCALATE: 0, pending: 0 };
  for (const v of state.vulns) {
    const d = state.results[v.cve_id];
    const rt = d ? route(d) : null;
    counts.all++;
    if (rt) counts[rt.disposition]++;
    else counts.pending++;

    if (!matchesSearch(v)) continue;
    if (state.filter === "AUTO" && (!rt || rt.disposition !== "AUTO")) continue;
    if (state.filter === "ESCALATE" && (!rt || rt.disposition !== "ESCALATE")) continue;
    if (state.filter === "pending" && d) continue;

    const li = document.createElement("li");
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    if (state.selected === v.cve_id) li.classList.add("selected");
    const kev = v.known_exploited ? `<span class="tag kev" title="CISA KEV: known exploited">KEV</span>` : "";
    li.innerHTML = `
      <div class="r1">
        <span class="sev ${sevClass(v.cvss || 0)}" title="cvss ${v.cvss}"></span>
        <span class="cve">${esc(v.cve_id)}</span>
        ${rt ? `<span class="disp ${rt.disposition}">${rt.disposition === "AUTO" ? "auto" : "esc"}</span>` : ""}
        <span class="asset">${esc(v.asset.name)}</span>
      </div>
      <div class="r2">
        <span class="kv">cvss ${fmt(v.cvss || 0, 1)}</span>
        <span class="kv">epss ${fmt(v.epss || 0)}</span>
        <span class="kv">${esc(v.asset.criticality_tier || "tier-?")}</span>
        ${kev}
      </div>`;
    const pick = () => { state.selected = v.cve_id; renderList(); renderDetail(); };
    li.onclick = pick;
    li.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } };
    ul.appendChild(li);
  }
  $("nAll").textContent = counts.all;
  $("nAuto").textContent = counts.AUTO;
  $("nEsc").textContent = counts.ESCALATE;
  $("nPending").textContent = counts.pending;
}

/* ---------------- classifiers panel ---------------- */

function renderQuestions() {
  const box = $("classifierList");
  box.innerHTML = "";
  for (const q of state.questions) {
    const div = document.createElement("div");
    div.className = "classifier";
    const crit = q.criteria
      ? `<details><summary>criteria</summary><pre>${esc(JSON.stringify(q.criteria, null, 2))}</pre></details>`
      : "";
    div.innerHTML = `
      ${typeChip(q.type)}
      <div class="qname">${esc(q.name)}</div>
      <div class="qinstr">${esc(q.instructions || "")}</div>
      ${crit}`;
    box.appendChild(div);
  }
}

/* ---------------- KPIs ---------------- */

function renderKpis() {
  const rs = Object.values(state.results);
  $("kTotal").textContent = state.vulns.length;
  $("kAuto").textContent = rs.filter((r) => route(r).disposition === "AUTO").length;
  $("kEsc").textContent = rs.filter((r) => route(r).disposition === "ESCALATE").length;
  $("kConf").textContent = rs.length
    ? fmt(rs.reduce((s, r) => s + r.action_confidence, 0) / rs.length)
    : "—";
  const lat = rs.map((r) => r.latency_ms).filter((v) => v > 0);
  $("kLat").textContent = lat.length ? fmtMs(lat.reduce((s, v) => s + v, 0) / lat.length) : "—";

  const tokens = rs.reduce((s, r) => s + tokensOf(r), 0);
  const cost = rs.reduce((s, r) => s + costOf(r), 0);
  const per = rs.length ? cost / rs.length : 0;
  $("kCost").textContent = rs.length ? "$" + per.toFixed(5) : "$0";
  $("kCostCard").title = rs.length
    ? `${rs.length} requests · ${fmtTok(tokens)} in-tokens · $${cost.toFixed(6)} total · ` +
      `$${state.meta.price}/Mtok in, outputs free${tokens ? " (estimated)" : ""}`
    : "cost appears once the first decision lands";
}

// Dragging the gate re-routes purely in the browser: count the flips and say so.
function renderGateDelta(prevT) {
  const el = $("gateDelta");
  const rs = Object.values(state.results);
  state.flipped = null;
  if (!rs.length || prevT == null || prevT === state.threshold) { el.hidden = true; el.textContent = ""; return; }
  const toEsc = [], toAuto = [];
  for (const r of rs) {
    const before = routeOf(r, prevT).disposition;
    const after = routeOf(r, state.threshold).disposition;
    if (before === after) continue;
    (after === "ESCALATE" ? toEsc : toAuto).push(r.cve_id);
  }
  const flips = toEsc.length + toAuto.length;
  if (!flips) { el.hidden = true; el.textContent = ""; return; }
  state.flipped = new Set([...toEsc, ...toAuto]);
  const parts = [];
  if (toEsc.length) parts.push(`${toEsc.length} auto → escalate`);
  if (toAuto.length) parts.push(`${toAuto.length} escalate → auto`);
  el.textContent = `↔ ${flips} flip${flips > 1 ? "s" : ""} (${parts.join(", ")}) · 0 requests · $0.00`;
  el.hidden = false;
}

function renderRunSummary() {
  const rs = Object.values(state.results);
  const el = $("runSummary");
  if (!rs.length) { el.textContent = ""; return; }
  const lat = rs.map((r) => r.latency_ms).filter((v) => v > 0);
  const avg = lat.length ? lat.reduce((s, v) => s + v, 0) / lat.length : 0;
  const tokens = rs.reduce((s, r) => s + tokensOf(r), 0);
  const cost = rs.reduce((s, r) => s + costOf(r), 0);
  el.innerHTML =
    `<b>${rs.length} requests</b> · <b>${state.meta.questions} answers per request</b> (one forward pass) · ` +
    `${fmtMs(avg)} avg · ${fmtTok(tokens)} in-tokens · est. <b>$${cost.toFixed(6)}</b> · ` +
    `$${state.meta.price}/Mtok in, outputs free`;
}

/* ---------------- live feed (dense rows) ---------------- */

const FEED_COLS = [
  ["cve", "CVE"], ["asset", "asset"], ["action", "next action"], ["conf", "confidence"],
  ["risk", "exploit 30d"], ["review", "analyst review"], ["ms", "ms"], ["disp", "routed"],
];

function renderFeedHead() {
  $("feedHead").innerHTML = FEED_COLS.map(([k, l]) => `<span class="c c-${k}">${l}</span>`).join("");
}

function feedIds() {
  let ids = state.order.filter((id) => {
    const v = vulnOf(id);
    return !v || matchesSearch(v);
  });
  const key = (id) => {
    const d = state.feed[id]?.d;
    if (!d) return null;
    const v = vulnOf(id) || {};
    return {
      escalated: route(d).disposition === "ESCALATE" ? 0 : 1,
      confidence: d.action_confidence,
      risk: -d.exploit_position,
      cvss: -(v.cvss || 0),
      arrival: ids.indexOf(id),
    };
  };
  if (state.sort !== "arrival") {
    ids = ids.slice().sort((a, b) => {
      const ka = key(a), kb = key(b);
      if (!ka || !kb) return 0;
      return ka[state.sort] - kb[state.sort];
    });
  }
  return ids;
}

function feedRow(id) {
  const f = state.feed[id];
  if (f.status === "pending") {
    return `<div class="frow pending"><span class="c c-cve">${esc(id)}</span><span class="c c-asset spinner">◌ asking…</span></div>`;
  }
  if (f.status === "error") {
    return `<div class="frow error"><span class="c c-cve">${esc(id)}</span><span class="c c-asset reason">✕ ${esc(f.error)}</span></div>`;
  }
  const d = f.d;
  const v = vulnOf(id) || {};
  const rt = route(d);
  const nl = d.detail.needs_analyst_review.probability;
  const esc_ = rt.disposition === "ESCALATE";
  const cells = [
    `<span class="c c-cve"><span class="sev ${sevClass(v.cvss || 0)}" title="cvss ${v.cvss}"></span>${esc(d.cve_id)}</span>`,
    `<span class="c c-asset">${esc(d.asset_name)}${v.known_exploited ? ' <span class="tag kev">KEV</span>' : ""}</span>`,
    `<span class="c c-action" style="color:${ACTION_COLORS[d.action] || "inherit"}">${esc(d.action)}</span>`,
    `<span class="c c-conf">${mbar(d.action_confidence, confColor(d.action_confidence), state.threshold, `confidence of the chosen action · gate ${fmt(state.threshold)}`)}</span>`,
    `<span class="c c-risk">${mbar(d.exploit_position, levelColor(d.exploit_position), null, `exploit likelihood in 30d · ${d.exploit_bucket} · expected score position`)}</span>`,
    `<span class="c c-review">${mbar(nl, nl >= REVIEWER_ESCALATE_AT ? "#fbbf24" : ACCENT, REVIEWER_ESCALATE_AT, `probability a human should review · escalates at ${REVIEWER_ESCALATE_AT}`)}</span>`,
    `<span class="c c-ms" title="wall-clock time of the single Jev request">${Math.round(d.latency_ms || 0)}</span>`,
    `<span class="c c-disp"><span class="disp ${rt.disposition}">${rt.disposition}</span></span>`,
  ];
  const reasons = rt.reasons.length ? `<div class="c-reason">⚠ ${esc(rt.reasons.join("; "))}</div>` : "";
  return `<div class="frow${esc_ ? " escalated" : ""}${state.selected === id ? " selected" : ""}${state.flipped?.has(id) ? " flipped" : ""}" tabindex="0" role="button"
    aria-label="${esc(`${d.cve_id} on ${d.asset_name}: ${d.action}, confidence ${fmt(d.action_confidence)}, ${rt.disposition}`)}"
    data-cve="${esc(id)}">${cells.join("")}${reasons}</div>`;
}

function renderFeed() {
  $("feed").innerHTML = state.order.length
    ? state.order.map(feedRow).join("")
    : `<div class="feed-empty">No decisions yet — press <b>▶ Run triage</b> to ask Jev about all ${state.vulns.length} CVEs, ${state.meta.questions} typed answers per request.</div>`;
}

function selectVuln(id) {
  state.selected = id;
  renderList();
  renderFeed();
  renderDetail();
}

function feedRowStart(e) {
  if (!state.feed[e.cve_id]) state.order.push(e.cve_id);
  state.feed[e.cve_id] = { status: "pending" };
  if (!state.selected) state.selected = e.cve_id;
  renderFeed();
}

function feedRowDone(d) {
  state.results[d.cve_id] = d;
  state.feed[d.cve_id] = { status: "done", d };
  state.runDone++;
  renderFeed(); renderKpis(); renderList(); renderRunSummary(); renderProgress();
  if (state.selected === d.cve_id) renderDetail();
}

function feedRowError(e) {
  state.feed[e.cve_id] = { status: "error", error: e.error };
  state.runDone++;
  renderFeed(); renderList(); renderProgress();
}

function renderProgress() {
  const hint = $("feedHint");
  if (state.running) {
    const secs = ((Date.now() - state.runStartedAt) / 1000).toFixed(1);
    hint.textContent = `— ${state.runDone}/${state.runTotal || state.vulns.length} analyzed · ${secs}s`;
  }
}

/* ---------------- detail pane ---------------- */

function factRow(k, v, cls) {
  return `<div class="fact"><span class="fk">${esc(k)}</span><span class="fv ${cls || ""}">${esc(v)}</span></div>`;
}

function stateFacts(v) {
  const a = v.asset || {};
  const tags = [
    a.criticality_tier || "tier-?",
    a.internet_exposed ? "internet-exposed" : "internal only",
    a.data_classification || "unclassified",
  ].map((t) => `<span class="tag">${esc(t)}</span>`).join("");
  return `
    <div class="facts">
      ${factRow("cvss", fmt(v.cvss || 0, 1), "sev-text " + sevClass(v.cvss || 0))}
      ${factRow("epss", fmt(v.epss || 0))}
      ${factRow("known exploited", v.known_exploited ? "yes (KEV)" : "no", v.known_exploited ? "hot" : "")}
    </div>
    <div class="tags">${tags}</div>
    <div class="desc"><b>${esc(v.title || "")}</b><p>${esc(v.description || "")}</p></div>`;
}

function renderDetail() {
  const box = $("detail");
  const v = vulnOf(state.selected);
  if (!v) { box.innerHTML = `<p class="muted">Select a vulnerability from the sidebar.</p>`; return; }
  const r = state.results[v.cve_id];
  const left = `
    <div>
      <h4>state sent to jev</h4>
      ${stateFacts(v)}
    </div>`;
  if (!r) {
    const queued = state.runTotal > 0 ? "this CVE is still queued in the run" : "press ▶ Run triage";
    box.innerHTML = `<div class="detail-grid">${left}<div><p class="muted">Not analyzed yet — ${queued}.</p></div></div>`;
    return;
  }
  const na = r.detail.next_action;
  const sc = r.detail.exploit_likelihood_30d;
  const nl = r.detail.needs_analyst_review.probability;
  const rt = route(r);
  const right = `
    <div>
    <div class="answer-meta">
      <span class="ms">⏱ ${fmtMs(r.latency_ms)}</span>
      <span class="muted">${esc(r.detail.model || "")}</span>
      <span class="dotsep">·</span>
      <span class="muted">${fmtTok(tokensOf(r))} in-tokens · est. $${costOf(r).toFixed(6)}</span>
      <span class="disp ${rt.disposition}">${rt.disposition}</span>
    </div>
    <h4>${typeChip("choice")} next_action — <span style="color:${ACTION_COLORS[na.choice] || "inherit"}">${esc(na.choice)}</span> <span style="color:${confColor(na.confidence)}">(conf ${fmt(na.confidence)})</span></h4>
    ${bars(na.probabilities, na.choice, "choice")}
    <h4>${typeChip("score")} exploit_likelihood_30d — <span style="color:${levelColor(r.exploit_position)}">${esc(r.exploit_bucket)} · ${fmt(r.exploit_position)}</span> <span style="color:${confColor(sc.confidence)}">(conf ${fmt(sc.confidence)})</span></h4>
    ${bars(labelScoreProbs(sc.probabilities, sc.legend), null, "score")}
    <h4>${typeChip("noul")} needs_analyst_review — ${fmt(nl)}</h4>
    ${bars({ yes: nl, no: 1 - nl }, null, "noul")}
    <div class="gate-note">
      gate ${fmt(state.threshold)} → confidence ${fmt(r.action_confidence)} ${r.action_confidence >= state.threshold ? "≥" : "<"} gate ·
      analyst review ${fmt(nl)} ${nl >= REVIEWER_ESCALATE_AT ? "≥" : "<"} ${REVIEWER_ESCALATE_AT}
      <b>${rt.disposition}</b>
    </div>
    ${rt.reasons.length ? `<div class="reason">⚠ ${esc(rt.reasons.join("; "))}</div>` : ""}
    ${payloadDetails(r.detail.request, r.detail.response)}
    </div>`;
  box.innerHTML = `<div class="detail-grid">${left}${right}</div>`;
}

/* ---------------- run ---------------- */

function renderAll() {
  renderList(); renderKpis(); renderFeed(); renderDetail(); renderRunSummary();
}

function setRunning(on) {
  state.running = on;
  $("runBtn").disabled = on;
  $("stopBtn").hidden = !on;
  $("statusDot").className = "dot " + (on ? "running" : "done");
  clearInterval(state.timer);
  if (on) state.timer = setInterval(renderProgress, 200); // live n/total + elapsed
}

function run() {
  stopRun(true);
  state.results = {}; state.feed = {}; state.order = []; state.flipped = null;
  $("gateDelta").hidden = true;
  state.runDone = 0; state.runTotal = state.vulns.length; state.runStartedAt = Date.now();
  renderAll();
  $("statusDot").className = "dot running";
  setRunning(true);
  renderProgress();

  const t = state.threshold;
  const es = new EventSource(`/api/triage/stream?threshold=${t}&model=${encodeURIComponent($("modelSel").value)}`);
  state.source = es;

  es.addEventListener("run_start", (e) => { $("modelBadge").textContent = JSON.parse(e.data).model; });
  es.addEventListener("vuln_start", (e) => feedRowStart(JSON.parse(e.data)));
  es.addEventListener("vuln_done", (e) => feedRowDone(JSON.parse(e.data)));
  es.addEventListener("vuln_error", (e) => feedRowError(JSON.parse(e.data)));
  es.addEventListener("run_done", () => {
    setRunning(false);
    $("feedHint").textContent = `— ${state.runDone}/${state.runTotal} analyzed in ${((Date.now() - state.runStartedAt) / 1000).toFixed(1)}s`;
    es.close(); state.source = null;
  });
  es.onerror = () => {
    if (!state.source) return; // closed on purpose
    setRunning(false);
    $("feedHint").textContent = "— connection lost";
    es.close(); state.source = null;
  };
}

function stopRun(quiet) {
  if (state.source) { const s = state.source; state.source = null; s.close(); }
  if (!quiet) {
    setRunning(false);
    for (const id of Object.keys(state.feed)) {
      if (state.feed[id].status === "pending") state.feed[id] = { status: "error", error: "stopped" };
    }
    renderFeed();
    $("feedHint").textContent = `— stopped after ${state.runDone} decisions`;
  }
}

/* ---------------- playground ---------------- */

function pgPrefillState() {
  const v = vulnOf(state.selected) || state.vulns[0];
  if (!v) return;
  $("pgState").value = JSON.stringify({ vulnerability: { ...v, asset: undefined }, asset: v.asset }, null, 2);
  pgValidate();
}

function pgPrefillQuestions() {
  // The questions editor is driven by the classifier studio's sets; the built-in
  // /api/questions payload is only the fallback when the studio failed to load.
  const sets = Studio.listSets();
  if (sets.length) return pgLoadSet(sets[0].id);
  const qs = {};
  for (const q of state.questions) {
    const { name, ...rest } = q;
    qs[name] = rest;
  }
  $("pgQuestions").value = JSON.stringify(qs, null, 2);
  pgValidate();
}

function pgSetOptions() {
  $("pgSet").innerHTML = Studio.listSets()
    .map((s) => `<option value="${esc(s.id)}">${esc(s.name)} · ${s.count} q${s.errors ? " · " + s.errors + " issue(s)" : ""}</option>`)
    .join("");
  if (state.pgSetId) $("pgSet").value = state.pgSetId;
}

function pgLoadSet(id) {
  const wire = Studio.wireFor(id);
  if (!wire) return;
  state.pgSetId = id;
  if (![...$("pgSet").options].some((o) => o.value === id)) pgSetOptions();
  $("pgSet").value = id;
  $("pgQuestions").value = JSON.stringify(wire, null, 2);
  pgValidate();
}

// The textarea stays the escape hatch: diverging from the set shows "edited".
function pgSyncModified() {
  const badge = $("pgSetModified");
  const current = $("pgQuestions").value.trim();
  let pristine = "";
  try {
    pristine = JSON.stringify(JSON.parse(current), null, 2);
  } catch (e) {
    pristine = current;
  }
  const wire = state.pgSetId ? Studio.wireFor(state.pgSetId) : null;
  const matches = wire && JSON.stringify(JSON.parse(pristine), null, 2) === JSON.stringify(wire, null, 2);
  badge.hidden = !!matches;
  return matches;
}

function pgUseSet(id) {
  pgLoadSet(id);
  showTab("playground");
}

// JSON errors are shown as you type, not only when you press Ask Jev.
function pgValidate() {
  let ok = true;
  const out = {};
  for (const [key, el, box] of [["state", $("pgState"), $("pgStateErr")], ["questions", $("pgQuestions"), $("pgQuestionsErr")]]) {
    try {
      out[key] = JSON.parse(el.value);
      box.textContent = "";
      el.classList.remove("invalid");
    } catch (e) {
      ok = false;
      out[key] = null;
      box.textContent = e.message;
      el.classList.add("invalid");
    }
  }
  if (ok) pgSyncModified();
  return ok ? out : null;
}

// One ask, shared by the playground and the studio's answer matrix.
async function askJev(st, qs) {
  const res = await fetch("/api/ask", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state: st, questions: qs, model: $("modelSel").value || null }),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

function meanSpread(values) {
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  return { mean, spread: Math.max(...values) - Math.min(...values) };
}

function pgAggregate(list) {
  const groups = {};
  for (const data of list) {
    for (const [name, a] of Object.entries(data.response.answers || {})) {
      const g = groups[name] || (groups[name] = { type: a.type, probs: {}, conf: [], choices: [], scores: [], legend: a.legend || {} });
      if (a.type === "noul") {
        (g.probs.yes = g.probs.yes || []).push(Number(a.noul));
        (g.probs.no = g.probs.no || []).push(1 - Number(a.noul));
      } else if (a.type === "score") {
        for (const [k, p] of Object.entries(a.probabilities || {})) {
          const label = legendName(g.legend[k], k);
          (g.probs[label] = g.probs[label] || []).push(Number(p));
        }
        g.scores.push(Number(a.score));
      } else {
        for (const [k, p] of Object.entries(a.probabilities || {})) (g.probs[k] = g.probs[k] || []).push(Number(p));
        g.choices.push(String(a.choice));
      }
      if (Number.isFinite(Number(a.confidence))) g.conf.push(Number(a.confidence));
    }
  }
  return groups;
}

function renderPgStable(name, g) {
  const entries = Object.entries(g.probs); // insertion order keeps score levels ascending
  const total = entries.length;
  const runs = entries[0] ? entries[0][1].length : 0;
  const rows = entries
    .map(([k, vals], i) => ({ k, i, ...meanSpread(vals) }));
  if (g.type !== "score") rows.sort((a, b) => b.mean - a.mean);
  const barsHtml = `<div class="bars">${rows
    .map((r) => barRow(r.k, r.mean, barColor(r.k, r.i, total, g.type, false), { spread: r.spread }))
    .join("")}</div>`;
  let headline;
  if (g.type === "choice") {
    const counts = {};
    for (const c of g.choices) counts[c] = (counts[c] || 0) + 1;
    const [mode, n] = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    headline = `<span style="color:${ACTION_COLORS[mode] || "inherit"}">${esc(mode)}</span> in ${n}/${g.choices.length} runs`;
  } else if (g.type === "score") {
    const s = meanSpread(g.scores);
    headline = `<span style="color:${levelColor(Math.min(1, s.mean / Math.max(total - 1, 1)))}">${fmt(s.mean)}</span> mean score ±${fmt(s.spread)}`;
  } else {
    const y = meanSpread(g.probs.yes);
    headline = `<span style="color:${y.mean >= 0.5 ? "#fbbf24" : "#34d399"}">${fmt(y.mean)}</span> mean yes · ±${fmt(y.spread)}`;
  }
  const conf = g.conf.length ? meanSpread(g.conf) : null;
  return `
    <div class="pg-answer">
      <h4>${typeChip(g.type)} ${esc(name)} — ${headline}${conf ? ` <span style="color:${confColor(conf.mean)}">(conf ${fmt(conf.mean)} ±${fmt(conf.spread)})</span>` : ""}</h4>
      ${barsHtml}
      <div class="stab">${runs} answers · bars = mean probability, ± = spread between the highest and lowest run</div>
    </div>`;
}

function renderPgAnswer(name, a) {
  if (a.type === "choice") {
    return `<div class="pg-answer"><h4>${typeChip("choice")} ${esc(name)} — <span style="color:${ACTION_COLORS[a.choice] || "inherit"}">${esc(a.choice)}</span> <span style="color:${confColor(a.confidence)}">(conf ${fmt(a.confidence)})</span></h4>${bars(a.probabilities, a.choice, "choice")}</div>`;
  }
  if (a.type === "score") {
    const labeled = labelScoreProbs(a.probabilities, a.legend);
    const position = (a.score || 0) / Math.max(Object.keys(labeled).length - 1, 1);
    return `<div class="pg-answer"><h4>${typeChip("score")} ${esc(name)} — <span style="color:${levelColor(position)}">${fmt(a.score)}</span> <span style="color:${confColor(a.confidence)}">(conf ${fmt(a.confidence)})</span></h4>${bars(labeled, null, "score")}</div>`;
  }
  return `<div class="pg-answer"><h4>${typeChip("noul")} ${esc(name)} — <span style="color:${a.noul >= 0.5 ? "#fbbf24" : "#34d399"}">${fmt(a.noul)}</span></h4>${bars({ yes: a.noul, no: 1 - a.noul }, null, "noul")}</div>`;
}

function pgSummary(list) {
  const lat = list.map((d) => Number(d.latency_ms) || 0).filter((v) => v > 0);
  const avg = lat.length ? lat.reduce((s, v) => s + v, 0) / lat.length : 0;
  const answers = Object.keys(list[0].response.answers || {}).length;
  const tok = list.reduce((s, d) => s + (Number(d.response.usage?.input_tokens) || 0), 0);
  const est = (tok / 1e6) * (state.meta.price || 0);
  const billed = list.reduce((s, d) => s + (Number(d.response.usage?.cost) || 0), 0);
  return `
    <div class="pg-summary">
      <span><b>${list.length} request${list.length > 1 ? "s" : ""}</b> → <b>${answers * list.length} typed answers</b>, no parsing</span>
      <span>⏱ ${fmtMs(avg)} avg</span>
      <span>${fmtTok(tok)} in-tokens</span>
      <span>${billed > 0 ? "billed $" + billed.toFixed(6) : "est. $" + est.toFixed(6)}</span>
    </div>`;
}

function renderPgResults(list) {
  let html = pgSummary(list);
  if (list.length > 1) {
    const groups = pgAggregate(list);
    for (const [name, g] of Object.entries(groups)) html += renderPgStable(name, g);
    html += payloadDetails(list[0].request, list[0].response);
  } else {
    for (const [name, a] of Object.entries(list[0].response.answers || {})) html += renderPgAnswer(name, a);
    html += payloadDetails(list[0].request, list[0].response);
  }
  $("pgResult").innerHTML = html;
}

async function pgSend() {
  const parsed = pgValidate();
  if (!parsed) { $("pgStatus").textContent = "fix the JSON above"; return; }
  const runs = Number($("pgRuns").value) || 1;
  $("pgSend").disabled = true;
  $("pgStatus").textContent = "asking…";
  $("pgResult").innerHTML = "";
  const list = [];
  $("pgSend").disabled = true;
  $("pgStatus").textContent = "asking…";
  $("pgResult").innerHTML = "";
  try {
    for (let i = 0; i < runs; i++) {
      if (runs > 1) $("pgStatus").textContent = `asking ${i + 1}/${runs}…`;
      const data = await askJev(parsed.state, parsed.questions);
      data.request = { state: parsed.state, questions: parsed.questions };
      list.push(data);
      renderPgResults(list);
      $("pgStatus").textContent = `${data.response.model} · ${fmtMs(data.latency_ms)}`;
    }
    if (runs > 1) $("pgStatus").textContent = `${runs} runs · ${list[0].response.model}`;
  } catch (e) {
    $("pgStatus").textContent = "request failed: " + e.message;
    if (!list.length) $("pgResult").innerHTML = `<div class="reason">✕ ${esc(e.message)}</div>`;
  } finally {
    $("pgSend").disabled = false;
  }
}

/* ---------------- tabs ---------------- */

function showTab(name) {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === name));
  document.querySelectorAll(".tabpage").forEach((x) => x.classList.toggle("active", x.id === "tab-" + name));
}

document.querySelectorAll(".tab").forEach((t) => {
  t.onclick = () => showTab(t.dataset.tab);
});

/* ---------------- boot ---------------- */

(async function boot() {
  const [meta, vulns, questions, sets] = await Promise.all([
    fetch("/api/meta").then((r) => r.json()).catch(() => ({})),
    fetch("/api/vulns").then((r) => r.json()),
    fetch("/api/questions").then((r) => r.json()),
    fetch("/api/classifier-sets").then((r) => r.json()).catch(() => []),
  ]);
  state.meta = { price: meta.price_per_mtok_in ?? 0.042, questions: meta.questions ?? 3 };
  state.vulns = vulns;
  state.questions = questions;
  if (meta.provider) $("providerBadge").textContent = meta.provider;
  $("modelSel").innerHTML =
    `<option value="">default model</option>` +
    (meta.models || []).map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join("");
  $("feedHint").textContent =
    `— ${state.vulns.length} CVEs × ${state.meta.questions} classifiers per request · press ▶ Run triage`;

  renderList(); renderKpis(); renderQuestions(); renderFeedHead(); renderFeed(); renderDetail();
  Studio.init(Array.isArray(sets) ? sets : [], {
    useSet: pgUseSet,
    ask: askJev,
    setsChanged: pgSetOptions,
    getState: () => {
      const parsed = pgValidate();
      if (!parsed) throw new Error("the playground state JSON is invalid");
      return parsed.state;
    },
  });
  pgPrefillState(); pgSetOptions(); pgPrefillQuestions();

  $("runBtn").onclick = run;
  $("stopBtn").onclick = () => stopRun(false);
  $("pgSend").onclick = pgSend;
  $("loadSelected").onclick = pgPrefillState;
  $("resetQuestions").onclick = pgPrefillQuestions;
  $("pgSet").onchange = (e) => pgLoadSet(e.target.value);
  $("search").oninput = (e) => { state.search = e.target.value; renderList(); renderFeed(); };
  $("sortSel").onchange = (e) => { state.sort = e.target.value; renderFeed(); };
  $("threshold").oninput = (e) => {
    const prevT = state.threshold;
    state.threshold = Number(e.target.value);
    $("thresholdVal").textContent = fmt(state.threshold);
    renderGateDelta(prevT);
    renderAll(); // re-route locally: the probabilities are already in hand
  };
  for (const el of [$("pgState"), $("pgQuestions")]) el.oninput = pgValidate;
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && $("tab-playground").classList.contains("active")) {
      e.preventDefault();
      pgSend();
    }
  });
  document.querySelectorAll(".chip").forEach((c) => {
    c.onclick = () => {
      document.querySelectorAll(".chip").forEach((x) => x.classList.remove("active"));
      c.classList.add("active");
      state.filter = c.dataset.f;
      renderList();
    };
  });
  $("feed").onclick = (e) => {
    const row = e.target.closest(".frow[data-cve]");
    if (row) selectVuln(row.dataset.cve);
  };
  $("feed").onkeydown = (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const row = e.target.closest(".frow[data-cve]");
    if (row) { e.preventDefault(); selectVuln(row.dataset.cve); }
  };

  // No triage on load: every run is a real billable call per CVE, so the operator
  // starts it (the sidebar and detail pane work before anything has run).
})();
