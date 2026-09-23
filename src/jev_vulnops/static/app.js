/* jev-vulnops dashboard: sidebar, live SSE feed, detail pane, API playground. */

const state = {
  vulns: [],
  questions: [],
  results: {},       // cve_id -> TriageDecision
  filter: "all",
  search: "",
  selected: null,
  source: null,
};

const $ = (id) => document.getElementById(id);

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

/* ---------------- sidebar ---------------- */

function renderList() {
  const ul = $("vulnList");
  ul.innerHTML = "";
  const q = state.search.toLowerCase();
  for (const v of state.vulns) {
    const r = state.results[v.cve_id];
    if (q && !v.cve_id.toLowerCase().includes(q) && !v.asset.name.toLowerCase().includes(q)) continue;
    if (state.filter === "AUTO" && (!r || r.disposition !== "AUTO")) continue;
    if (state.filter === "ESCALATE" && (!r || r.disposition !== "ESCALATE")) continue;
    if (state.filter === "pending" && r) continue;

    const li = document.createElement("li");
    if (state.selected === v.cve_id) li.classList.add("selected");
    li.innerHTML = `
      <span class="sev ${sevClass(v.cvss || 0)}"></span>
      <span class="cve">${esc(v.cve_id)}</span>
      ${r ? `<span class="disp ${r.disposition}">${r.disposition === "AUTO" ? "auto" : "esc"}</span>` : ""}
      <span class="asset">${esc(v.asset.name)}</span>`;
    li.onclick = () => { state.selected = v.cve_id; renderList(); renderDetail(); };
    ul.appendChild(li);
  }
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
      <div class="qtype">${esc(q.type)}</div>
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
  $("kAuto").textContent = rs.filter((r) => r.disposition === "AUTO").length;
  $("kEsc").textContent = rs.filter((r) => r.disposition === "ESCALATE").length;
  $("kConf").textContent = rs.length
    ? fmt(rs.reduce((s, r) => s + r.action_confidence, 0) / rs.length)
    : "—";
  const cost = rs.reduce((s, r) => s + (r.detail?.usage?.cost || 0), 0);
  $("kCost").textContent = cost > 0 ? "$" + cost.toFixed(5) : "$0";
}

/* ---------------- shared renderers ---------------- */

function bars(probabilities, winner) {
  const rows = Object.entries(probabilities || {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, p]) => `
      <div class="bar-row">
        <span class="label">${esc(k)}</span>
        <span class="bar-track"><span class="bar-fill ${String(k) === String(winner) ? "winner" : ""}" style="width:${(p * 100).toFixed(1)}%"></span></span>
        <span class="val">${fmt(p)}</span>
      </div>`)
    .join("");
  return `<div class="bars">${rows}</div>`;
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

/* ---------------- live feed ---------------- */

function feedCardStart(e) {
  const card = document.createElement("div");
  card.className = "feed-card";
  card.id = "feed-" + e.cve_id;
  card.innerHTML = `
    <div class="head">
      <span class="cve">${esc(e.cve_id)}</span>
      <span class="asset">${esc(e.asset)}</span>
      <span class="spinner">◌ analyzing…</span>
    </div>`;
  $("feed").prepend(card);
}

function feedCardDone(d) {
  const card = $("feed-" + d.cve_id);
  if (!card) return;
  const na = d.detail.next_action;
  const nl = d.detail.needs_analyst_review;
  card.innerHTML = `
    <div class="head">
      <span class="sev ${sevClass(d.exploit_position * 10)}"></span>
      <span class="cve">${esc(d.cve_id)}</span>
      <span class="asset">${esc(d.asset_name)}</span>
      <span class="disp ${d.disposition}">${d.disposition}</span>
      <span class="action">${esc(d.action)}</span>
      <span class="due">${d.due_days ? d.due_days + "d SLA" : ""}</span>
    </div>
    <div class="bars">
      <div class="bar-row"><span class="label">confidence</span>
        <span class="bar-track"><span class="bar-fill ${d.action_confidence >= 0.75 ? "winner" : ""}" style="width:${(d.action_confidence * 100).toFixed(1)}%"></span></span>
        <span class="val">${fmt(d.action_confidence)}</span></div>
      <div class="bar-row"><span class="label">exploit 30d (${esc(d.exploit_bucket)})</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(d.exploit_position * 100).toFixed(1)}%"></span></span>
        <span class="val">${fmt(d.exploit_position)}</span></div>
      <div class="bar-row"><span class="label">analyst review</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(nl.probability * 100).toFixed(1)}%"></span></span>
        <span class="val">${fmt(nl.probability)}</span></div>
    </div>
    ${d.reasons.length ? `<div class="reason">⚠ ${esc(d.reasons.join("; "))}</div>` : ""}
    <details class="payload"><summary>▸ next_action distribution</summary>${bars(na.probabilities, na.choice)}</details>
    ${payloadDetails(d.detail.request, d.detail.response)}`;
}

function feedCardError(e) {
  const card = $("feed-" + e.cve_id);
  if (!card) return;
  card.classList.add("error");
  card.innerHTML = `<div class="head"><span class="cve">${esc(e.cve_id)}</span><span class="reason">✕ ${esc(e.error)}</span></div>`;
}

/* ---------------- detail pane ---------------- */

function renderDetail() {
  const box = $("detail");
  const v = state.vulns.find((x) => x.cve_id === state.selected);
  if (!v) { box.innerHTML = `<p class="muted">Select a vulnerability from the sidebar.</p>`; return; }
  const r = state.results[v.cve_id];
  let right = `<p class="muted">Not analyzed yet — press ▶ Run triage.</p>`;
  if (r) {
    const na = r.detail.next_action;
    const sc = r.detail.exploit_likelihood_30d;
    right = `
      <h4>next_action — ${esc(na.choice)} (conf ${fmt(na.confidence)})</h4>
      ${bars(na.probabilities, na.choice)}
      <h4>exploit_likelihood_30d — ${esc(r.exploit_bucket)} · ${fmt(r.exploit_position)} (conf ${fmt(sc.confidence)})</h4>
      ${bars(sc.probabilities, null)}
      <h4>needs_analyst_review — ${fmt(r.detail.needs_analyst_review.probability)}</h4>
      ${r.reasons.length ? `<div class="reason">⚠ ${esc(r.reasons.join("; "))}</div>` : ""}
      ${payloadDetails(r.detail.request, r.detail.response)}`;
  }
  box.innerHTML = `
    <div class="detail-grid">
      <div>
        <h4>state sent to jev</h4>
        <pre>${esc(JSON.stringify({ vulnerability: { ...v, asset: undefined }, asset: v.asset }, null, 2))}</pre>
      </div>
      <div>${right}</div>
    </div>`;
}

/* ---------------- run ---------------- */

function run() {
  if (state.source) state.source.close();
  state.results = {};
  renderKpis(); renderList();
  $("feed").innerHTML = "";
  $("feedHint").textContent = "— streaming";
  $("statusDot").className = "dot running";
  $("runBtn").disabled = true;

  const t = $("threshold").value;
  const m = $("modelSel").value;
  const es = new EventSource(`/api/triage/stream?threshold=${t}&model=${encodeURIComponent(m)}`);
  state.source = es;

  es.addEventListener("run_start", (e) => { $("modelBadge").textContent = JSON.parse(e.data).model; });
  es.addEventListener("vuln_start", (e) => feedCardStart(JSON.parse(e.data)));
  es.addEventListener("vuln_done", (e) => {
    const d = JSON.parse(e.data);
    state.results[d.cve_id] = d;
    feedCardDone(d);
    renderKpis(); renderList();
    if (state.selected === d.cve_id) renderDetail();
  });
  es.addEventListener("vuln_error", (e) => feedCardError(JSON.parse(e.data)));
  es.addEventListener("run_done", () => {
    $("statusDot").className = "dot done";
    $("runBtn").disabled = false;
    $("feedHint").textContent = "— run complete";
    es.close();
  });
  es.onerror = () => {
    $("statusDot").className = "dot idle";
    $("runBtn").disabled = false;
    $("feedHint").textContent = "— connection lost";
    es.close();
  };
}

/* ---------------- playground ---------------- */

function pgPrefillState() {
  const v = state.vulns.find((x) => x.cve_id === state.selected) || state.vulns[0];
  if (!v) return;
  $("pgState").value = JSON.stringify({ vulnerability: { ...v, asset: undefined }, asset: v.asset }, null, 2);
}

function pgPrefillQuestions() {
  const qs = {};
  for (const q of state.questions) {
    const { name, ...rest } = q;
    qs[name] = rest;
  }
  $("pgQuestions").value = JSON.stringify(qs, null, 2);
}

function renderPgAnswer(name, a) {
  if (a.type === "choice") {
    return `<div class="pg-answer"><h4>${esc(name)} — choice: ${esc(a.choice)} (conf ${fmt(a.confidence)})</h4>${bars(a.probabilities, a.choice)}</div>`;
  }
  if (a.type === "score") {
    const legend = a.legend || {};
    const probs = {};
    for (const [k, v] of Object.entries(a.probabilities || {})) probs[legend[k] ?? k] = v;
    return `<div class="pg-answer"><h4>${esc(name)} — score: ${fmt(a.score)} (conf ${fmt(a.confidence)})</h4>${bars(probs, null)}</div>`;
  }
  return `<div class="pg-answer"><h4>${esc(name)} — noul: ${fmt(a.noul)}</h4>${bars({ yes: a.noul, no: 1 - a.noul }, null)}</div>`;
}

async function pgSend() {
  let st, qs;
  try { st = JSON.parse($("pgState").value); } catch (e) { $("pgStatus").textContent = "state JSON invalid: " + e.message; return; }
  try { qs = JSON.parse($("pgQuestions").value); } catch (e) { $("pgStatus").textContent = "questions JSON invalid: " + e.message; return; }

  $("pgStatus").textContent = "asking…";
  $("pgSend").disabled = true;
  $("pgResult").innerHTML = "";
  try {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state: st, questions: qs, model: $("modelSel").value || null }),
    });
    const data = await res.json();
    if (!data.ok) {
      $("pgStatus").textContent = "error";
      $("pgResult").innerHTML = `<div class="reason">✕ ${esc(data.error)}</div>`;
      return;
    }
    const resp = data.response;
    $("pgStatus").textContent = `${resp.model} · ${JSON.stringify(resp.usage)}`;
    let html = "";
    for (const [name, a] of Object.entries(resp.answers || {})) html += renderPgAnswer(name, a);
    html += payloadDetails({ state: st, questions: qs }, resp);
    $("pgResult").innerHTML = html;
  } catch (e) {
    $("pgStatus").textContent = "request failed: " + e.message;
  } finally {
    $("pgSend").disabled = false;
  }
}

/* ---------------- tabs ---------------- */

document.querySelectorAll(".tab").forEach((t) => {
  t.onclick = () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tabpage").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-" + t.dataset.tab).classList.add("active");
  };
});

/* ---------------- boot ---------------- */

(async function boot() {
  state.vulns = await (await fetch("/api/vulns")).json();
  state.questions = await (await fetch("/api/questions")).json();
  renderList(); renderKpis(); renderQuestions();
  pgPrefillState(); pgPrefillQuestions();
  $("runBtn").onclick = run;
  $("pgSend").onclick = pgSend;
  $("loadSelected").onclick = pgPrefillState;
  $("resetQuestions").onclick = pgPrefillQuestions;
  $("search").oninput = (e) => { state.search = e.target.value; renderList(); };
  $("threshold").oninput = (e) => { $("thresholdVal").textContent = fmt(e.target.value); };
  document.querySelectorAll(".chip").forEach((c) => {
    c.onclick = () => {
      document.querySelectorAll(".chip").forEach((x) => x.classList.remove("active"));
      c.classList.add("active");
      state.filter = c.dataset.f;
      renderList();
    };
  });
})();
