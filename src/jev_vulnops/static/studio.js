/* Classifier studio: build named sets of classifiers as a matrix (questions ×
   type/instructions/criteria), then use one in the API playground or test
   several against the same state and read the answer matrix side by side.

   Sets live in the browser (localStorage) so experiments survive a reload;
   server-provided sets are marked built-in and can be restored. Wire format
   conversion and validation live here so the studio cannot build a request the
   API would reject. */

const Studio = (function () {
  const STORAGE_KEY = "jev-vulnops.classifier-sets.v1";
  const TYPES = ["choice", "score", "noul"];

  let sets = [];
  let serverSets = [];
  let selectedId = null;
  const checked = new Set();
  const open = new Set(); // question rows with their criteria expanded
  let hooks = {};
  let matrixRun = null; // last "test selected sets" result
  let statusMsg = "state comes from the API playground editor";

  function setStatus(msg) {
    statusMsg = msg;
    const el = document.getElementById("studioStatus");
    if (el) el.textContent = msg;
  }

  /* ---------------- wire format ---------------- */

  function criteriaFromWire(name, q) {
    if (q.type === "noul") return [];
    if (q.type === "score") {
      return (q.criteria || []).map((c, i) => ({
        name: (c && c.name) || `level-${i}`,
        description: (c && c.description) || "",
      }));
    }
    return Object.entries(q.criteria || {}).map(([k, v]) => ({
      name: k,
      description: typeof v === "string" ? v : ((v && (v.name || v.description)) || ""),
    }));
  }

  // map of questions (or the /api/questions list) -> editable array
  function questionsFromWire(source) {
    const entries = Array.isArray(source)
      ? source.map((q) => [q.name, q])
      : Object.entries(source || {});
    return entries.map(([name, q]) => ({
      name,
      type: TYPES.includes(q.type) ? q.type : "choice",
      instructions: q.instructions || "",
      criteria: criteriaFromWire(name, q),
    }));
  }

  // editable array -> the object /api/ask expects
  function toWire(questions) {
    const out = {};
    for (const q of questions) {
      const name = String(q.name || "").trim();
      if (q.type === "noul") out[name] = { type: "noul", instructions: q.instructions };
      else if (q.type === "score")
        out[name] = {
          type: "score",
          instructions: q.instructions,
          criteria: q.criteria.map((c) => ({ name: c.name, description: c.description })),
        };
      else
        out[name] = {
          type: "choice",
          instructions: q.instructions,
          criteria: Object.fromEntries(q.criteria.map((c) => [c.name, c.description])),
        };
    }
    return out;
  }

  function setFromWire(s) {
    return {
      id: String(s.id || slug(s.name || "set")),
      name: s.name || s.id || "untitled set",
      description: s.description || "",
      builtin: !!s.builtin,
      questions: questionsFromWire(s.questions),
    };
  }

  function slug(s) {
    return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "set";
  }

  /* ---------------- validation ---------------- */

  function validateSet(s) {
    const errors = [];
    if (!String(s.name || "").trim()) errors.push("set needs a name");
    if (!s.questions || !s.questions.length) errors.push("set needs at least one question");
    const seen = new Set();
    for (const q of s.questions || []) {
      const at = String(q.name || "").trim() || "(unnamed)";
      if (!String(q.name || "").trim()) errors.push("every question needs a name");
      else if (/\s/.test(q.name)) errors.push(`${at}: name must not contain spaces`);
      if (seen.has(q.name)) errors.push(`${at}: duplicate question name`);
      seen.add(q.name);
      if (!String(q.instructions || "").trim()) errors.push(`${at}: instructions are required`);
      if (!TYPES.includes(q.type)) errors.push(`${at}: type must be choice, score or noul`);
      if (q.type === "noul") continue;
      const crit = q.criteria || [];
      if (crit.length < 2) errors.push(`${at}: ${q.type} needs at least 2 criteria`);
      const labels = new Set();
      for (const c of crit) {
        if (!String(c.name || "").trim()) errors.push(`${at}: every ${q.type} criterion needs a label`);
        else if (labels.has(c.name)) errors.push(`${at}: duplicate criterion ${c.name}`);
        labels.add(c.name);
        if (!String(c.description || "").trim())
          errors.push(`${at}: ${c.name || "criterion"} needs a description`);
      }
    }
    return errors;
  }

  function errorsFor(id) {
    const s = sets.find((x) => x.id === id);
    return s ? validateSet(s) : ["unknown set"];
  }

  /* ---------------- persistence ---------------- */

  function persist() {
    const payload = sets.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description,
      builtin: !!s.builtin,
      questions: toWire(s.questions),
    }));
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    } catch (e) {
      /* private mode / quota: the studio still works for this page load */
    }
  }

  function restore() {
    // Pristine built-ins, but keep anything the user created.
    const customs = sets.filter((s) => !s.builtin);
    sets = merge(serverSets.map(setFromWire), customs);
    if (!sets.find((s) => s.id === selectedId)) selectedId = sets.length ? sets[0].id : null;
    persist();
    notifyList();
    render();
  }

  function readStored() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed.map(setFromWire) : [];
    } catch (e) {
      return [];
    }
  }

  function merge(base, stored) {
    const byId = new Map(base.map((s) => [s.id, s]));
    const out = base.slice();
    for (const s of stored) {
      if (byId.has(s.id)) {
        const i = out.findIndex((x) => x.id === s.id);
        out[i] = { ...s, builtin: true };
      } else {
        out.push({ ...s, builtin: false });
      }
    }
    return out;
  }

  function notifyList() {
    if (hooks.setsChanged) hooks.setsChanged();
  }

  /* ---------------- set operations ---------------- */

  function uniqueId(name, taken) {
    let id = slug(name);
    let i = 2;
    while (taken.has(id)) id = `${slug(name)}-${i++}`;
    return id;
  }

  function newSet(kind) {
    const taken = new Set(sets.map((s) => s.id));
    const s = {
      id: uniqueId(kind === "blank" ? "blank" : `copy-of-${selectedId}`, taken),
      name: kind === "blank" ? "New set" : `${(find(selectedId) || {}).name || "set"} (copy)`,
      description: "",
      builtin: false,
      questions:
        kind === "blank"
          ? []
          : JSON.parse(JSON.stringify((find(selectedId) || { questions: [] }).questions)),
    };
    sets.push(s);
    selectedId = s.id;
    checked.add(s.id);
    persist();
    notifyList();
    render();
  }

  function deleteSet(id) {
    sets = sets.filter((s) => s.id !== id);
    checked.delete(id);
    if (selectedId === id) selectedId = sets.length ? sets[0].id : null;
    persist();
    notifyList();
    render();
  }

  function find(id) {
    return sets.find((s) => s.id === id);
  }

  function addQuestion(type) {
    const s = find(selectedId);
    if (!s) return;
    const n = s.questions.length + 1;
    s.questions.push({
      name: type === "choice" ? `q${n}` : type === "score" ? `score_${n}` : `flag_${n}`,
      type,
      instructions: "",
      criteria:
        type === "noul" ? [] : [
          { name: "option-a", description: "" },
          { name: "option-b", description: "" },
        ],
    });
    open.add(`${s.id}/${s.questions.length - 1}`);
    persist();
    render();
  }

  /* ---------------- rendering ---------------- */

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function render() {
    renderSetList();
    renderEditor();
    renderMatrixRun();
  }

  function renderSetList() {
    const box = document.getElementById("setList");
    if (!box) return;
    box.innerHTML = sets
      .map((s) => {
        const errs = validateSet(s);
        const edited = s.builtin && isEdited(s);
        return `<li class="setrow${s.id === selectedId ? " selected" : ""}${errs.length ? " invalid" : ""}" data-id="${esc(s.id)}">
          <input type="checkbox" data-act="check" ${checked.has(s.id) ? "checked" : ""}
            aria-label="include ${esc(s.name)} in the test matrix" tabindex="0">
          <button class="setname" data-act="select" title="${esc(s.name)} — ${s.questions.length} question(s)">${esc(s.name)}</button>
          <span class="setmeta">${s.questions.length} q</span>
          ${s.builtin ? '<span class="tag">built-in</span>' : '<span class="tag custom">custom</span>'}
          ${edited ? '<span class="tag warn">edited</span>' : ""}
          ${errs.length ? `<span class="tag err" title="${esc(errs.join(" · "))}">${errs.length} issue${errs.length > 1 ? "s" : ""}</span>` : ""}
        </li>`;
      })
      .join("");
    document.getElementById("nSets").textContent = sets.length;
    document.getElementById("nChecked").textContent = checked.size;
  }

  function isEdited(s) {
    const orig = serverSets.find((x) => x.id === s.id);
    if (!orig) return true;
    return JSON.stringify(toWire(s.questions)) !== JSON.stringify(toWire(questionsFromWire(orig.questions)));
  }

  function renderEditor() {
    const s = find(selectedId);
    const host = document.getElementById("setEditor");
    if (!host) return;
    if (!s) {
      host.innerHTML = `<p class="muted">No set selected — create one to start.</p>`;
      return;
    }
    const chosen = sets.filter((x) => checked.has(x.id));
    const blocked = chosen.filter((x) => validateSet(x).length);
    host.innerHTML = `
      <div class="set-head">
        <input id="setName" class="set-name" value="${esc(s.name)}" aria-label="set name" data-field="set-name">
        <input id="setDesc" class="set-desc" value="${esc(s.description)}" placeholder="what this set is testing…" title="${esc(s.description)}"
          aria-label="set description" data-field="set-desc">
        <span class="set-tags">
          ${s.builtin ? '<span class="tag">built-in</span>' : '<span class="tag custom">custom</span>'}
          ${s.builtin && isEdited(s) ? '<span class="tag warn">edited</span>' : ""}
        </span>
      </div>
      <div class="matrix-head">
        <span>question</span><span>type</span><span>instructions</span><span>criteria</span><span></span>
      </div>
      <div id="matrix">${s.questions.map((q, i) => matrixRow(s, q, i)).join("") ||
        `<p class="muted pad">Empty set — add a classifier below.</p>`}</div>
      <div class="matrix-actions">
        <button class="btn-ghost" data-act="add" data-type="choice">+ choice</button>
        <button class="btn-ghost" data-act="add" data-type="score">+ score</button>
        <button class="btn-ghost" data-act="add" data-type="noul">+ noul</button>
        <span class="spacer"></span>
        <button class="btn-ghost" data-act="delete">delete set</button>
      </div>
      <div class="vali" id="setValidation"></div>
      <div class="studio-actions">
        <button class="btn-primary" data-act="use">Use in API playground</button>
        <button class="btn-primary secondary" data-act="test"
          ${chosen.length && !blocked.length ? "" : "disabled"}
          title="${blocked.length ? esc(blocked.map((x) => x.name).join(", ") + " still has validation errors") : "run the checked sets against the playground state"}">
          Test ${chosen.length || ""} selected set${chosen.length === 1 ? "" : "s"} ▶
        </button>
        <span class="muted" id="studioStatus">${esc(statusMsg)}</span>
      </div>
      <div id="matrixResult"></div>`;
    renderValidation();
  }

  function matrixRow(s, q, i) {
    const key = `${s.id}/${i}`;
    const isOpen = open.has(key);
    const critLabel =
      q.type === "noul" ? "P(yes) only" : `${q.criteria.length} ${q.type === "score" ? "levels" : "options"}`;
    return `
      <div class="mrow${isOpen ? " open" : ""}" data-row="${i}">
        <button class="qname" data-act="q-toggle" title="edit criteria for ${esc(q.name)}">${esc(q.name)}</button>
        <select data-act="q-type" aria-label="question type">${TYPES.map(
          (t) => `<option value="${t}" ${t === q.type ? "selected" : ""}>${t}</option>`,
        ).join("")}</select>
        <input class="qinstr" data-act="q-instr" value="${esc(q.instructions)}" title="${esc(q.instructions)}" placeholder="instructions…">
        <button class="critsum" data-act="q-toggle" title="edit criteria">${critLabel} ▾</button>
        <span class="qacts">
          <button data-act="q-up" title="move up">↑</button>
          <button data-act="q-down" title="move down">↓</button>
          <button data-act="q-del" title="remove question">✕</button>
        </span>
        ${isOpen ? criteriaEditor(q) : ""}
      </div>`;
  }

  function criteriaEditor(q) {
    if (q.type === "noul") {
      return `<div class="crit"><p class="muted pad">noul needs no criteria: Jev returns P(yes) for the instruction above.</p></div>`;
    }
    const hint =
      q.type === "score"
        ? "ordered low → high; the score answer is the probability-weighted position on this scale"
        : "one row per option; the choice answer picks one and reports the probability of each";
    return `<div class="crit">
      <div class="crit-head"><span>label</span><span>description</span><span></span></div>
      ${q.criteria
        .map(
          (c, j) => `<div class="crow" data-crit="${j}">
            <input data-act="c-name" value="${esc(c.name)}" placeholder="e.g. remediate-now">
            <input data-act="c-desc" value="${esc(c.description)}" placeholder="what makes this the right answer">
            <button data-act="c-del" title="remove">✕</button>
          </div>`,
        )
        .join("")}
      <div class="crit-foot"><button class="btn-ghost" data-act="c-add">+ criterion</button>
        <span class="muted">${hint}</span></div>
    </div>`;
  }

  function renderValidation() {
    const box = document.getElementById("setValidation");
    if (!box) return;
    const errs = selectedId ? errorsFor(selectedId) : [];
    box.innerHTML = errs.length
      ? `<div class="vali-err">${errs.map((e) => `✕ ${esc(e)}`).join("<br>")}</div>`
      : `<div class="vali-ok">✓ valid — ${find(selectedId).questions.length} question(s), one request</div>`;
  }

  function miniBar(v, color) {
    const w = Math.max(0, Math.min(1, Number(v) || 0)) * 100;
    return `<span class="bar-track mini"><span class="bar-fill" style="width:${w.toFixed(1)}%;background:${color}"></span></span>`;
  }

  function renderMatrixRun() {
    const host = document.getElementById("matrixResult");
    if (!host || !matrixRun) return;
    const cols = [];
    for (const row of matrixRun.rows) for (const q of row.questions) if (!cols.includes(q)) cols.push(q);
    const head = `<thead><tr><th>set</th>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}<th>ms</th><th>tokens</th></tr></thead>`;
    const body = matrixRun.rows
      .map((r) => {
        const cells = cols
          .map((c) => {
            const a = r.answers[c];
            if (!a) return `<td class="absent">—</td>`;
            return `<td>${answerCell(a)}</td>`;
          })
          .join("");
        return `<tr><th class="rowhead" title="${esc(r.description || "")}">${esc(r.name)}${
          r.error ? ' <span class="tag err">error</span>' : ""
        }</th>${cells}<td class="num">${Math.round(r.ms || 0)}</td><td class="num">${
          r.tokens ? (r.tokens / 1000).toFixed(1) + "k" : "—"
        }</td></tr>`;
      })
      .join("");
    host.innerHTML = `
      <h4 class="run-title">answer matrix <span class="muted">— same state, ${matrixRun.rows.length} classifier set(s)</span></h4>
      <div class="matrix-scroll"><table class="answer-matrix">${head}<tbody>${body}</tbody></table></div>
      <p class="muted note">Cells show the chosen option / expected score / P(yes) with its confidence. Differing columns are where the wording changed the answer.</p>`;
  }

  function answerCell(a) {
    if (a.error) return `<span class="reason">✕ ${esc(a.error)}</span>`;
    if (a.type === "choice")
      return `<div class="acell"><b style="color:${ACTION_COLORS[a.choice] || "inherit"}">${esc(a.choice)}</b>
        ${miniBar(a.confidence, confColor(a.confidence))}<span class="num">${fmt(a.confidence)}</span></div>`;
    if (a.type === "score")
      return `<div class="acell"><b>${fmt(a.score)}</b>${miniBar(a.confidence, confColor(a.confidence))}
        <span class="num">${fmt(a.confidence)}</span></div>`;
    return `<div class="acell"><b style="color:${a.noul >= 0.5 ? "#fbbf24" : "#34d399"}">${fmt(a.noul)}</b>
      ${miniBar(a.noul, a.noul >= 0.5 ? "#fbbf24" : ACCENT)}<span class="num">P(yes)</span></div>`;
  }

  /* ---------------- testing ---------------- */

  async function testSelected() {
    const chosen = sets.filter((s) => checked.has(s.id));
    if (!chosen.length) return;
    let state;
    try {
      state = hooks.getState();
    } catch (e) {
      setStatus(`cannot read the playground state: ${e.message}`);
      return;
    }
    const invalid = chosen.map((s) => [s, validateSet(s)]).find(([, errs]) => errs.length);
    if (invalid) {
      selectedId = invalid[0].id;
      setStatus(`"${invalid[0].name}" is not valid yet`);
      render();
      return;
    }
    const rows = chosen.map((s) => ({ name: s.name, description: s.description, id: s.id, questions: [], answers: {} }));
    matrixRun = { rows };
    renderMatrixRun();
    setStatus("running…");
    for (const [i, s] of chosen.entries()) {
      const row = rows[i];
      row.questions = s.questions.map((q) => q.name);
      try {
        const data = await hooks.ask(state, toWire(s.questions));
        row.ms = Number(data.latency_ms) || 0;
        row.tokens = Number(data.response.usage && data.response.usage.input_tokens) || 0;
        row.answers = data.response.answers || {};
      } catch (e) {
        row.error = String(e.message || e);
        for (const q of row.questions) row.answers[q] = { error: row.error, type: "choice" };
      }
      setStatus(`${i + 1}/${chosen.length} sets answered`);
      renderMatrixRun();
    }
    render();
  }

  /* ---------------- events ---------------- */

  function onListClick(e) {
    const li = e.target.closest("[data-id]");
    if (!li) return;
    const id = li.dataset.id;
    const act = e.target.dataset.act;
    if (act === "check") {
      e.target.checked ? checked.add(id) : checked.delete(id);
      renderSetList();
      renderEditor();
      return;
    }
    selectedId = id;
    persist();
    render();
  }

  function onEditorInput(e) {
    const s = find(selectedId);
    if (!s) return;
    const t = e.target;
    const field = t.dataset.field || t.dataset.act;
    if (field === "set-name") {
      s.name = t.value;
      persist();
      renderSetList();
      return;
    }
    if (field === "set-desc") {
      s.description = t.value;
      persist();
      return;
    }
    const row = t.closest("[data-row]");
    if (!row) return;
    const q = s.questions[Number(row.dataset.row)];
    if (!q) return;
    if (field === "q-instr") q.instructions = t.value;
    if (field === "q-type") changeType(s, q, t.value);
    if (field === "c-name" || field === "c-desc") {
      const crow = t.closest("[data-crit]");
      const c = q.criteria[Number(crow.dataset.crit)];
      if (c) c[field === "c-name" ? "name" : "description"] = t.value;
    }
    persist();
    renderValidation();
    renderSetList();
  }

  function changeType(s, q, type) {
    q.type = type;
    if (type === "noul") q.criteria = [];
    else if (!q.criteria.length)
      q.criteria = [
        { name: "option-a", description: "" },
        { name: "option-b", description: "" },
      ];
    open.add(`${s.id}/${s.questions.indexOf(q)}`);
    renderEditor();
  }

  function onEditorClick(e) {
    const s = find(selectedId);
    const btn = e.target.closest("[data-act]");
    if (!btn || !s) return;
    const act = btn.dataset.act;
    const row = btn.closest("[data-row]");
    const i = row ? Number(row.dataset.row) : -1;
    const key = `${s.id}/${i}`;

    if (act === "q-toggle") {
      open.has(key) ? open.delete(key) : open.add(key);
      renderEditor();
    } else if (act === "q-del") {
      s.questions.splice(i, 1);
      persist();
      render();
    } else if (act === "q-up" || act === "q-down") {
      const j = act === "q-up" ? i - 1 : i + 1;
      if (j < 0 || j >= s.questions.length) return;
      [s.questions[i], s.questions[j]] = [s.questions[j], s.questions[i]];
      persist();
      renderEditor();
    } else if (act === "add") {
      addQuestion(btn.dataset.type);
    } else if (act === "delete") {
      deleteSet(s.id);
    } else if (act === "c-add") {
      s.questions[i].criteria.push({ name: `option-${String.fromCharCode(97 + s.questions[i].criteria.length)}`, description: "" });
      persist();
      renderEditor();
    } else if (act === "c-del") {
      s.questions[i].criteria.splice(Number(btn.closest("[data-crit]").dataset.crit), 1);
      persist();
      renderEditor();
    } else if (act === "use") {
      hooks.useSet(s.id);
    } else if (act === "test") {
      testSelected();
    }
  }

  /* ---------------- import / export ---------------- */

  function exportSets() {
    const payload = { sets: sets.map((s) => ({ id: s.id, name: s.name, description: s.description, questions: toWire(s.questions) })) };
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "classifier-sets.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  function importSets(file) {
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const raw = JSON.parse(String(reader.result));
        const entries = Array.isArray(raw) ? raw : raw.sets;
        if (!Array.isArray(entries)) throw new Error("expected an array of sets");
        const taken = new Set(sets.map((s) => s.id));
        for (const entry of entries) {
          const s = setFromWire({ ...entry, builtin: false });
          s.id = uniqueId(s.id, taken);
          taken.add(s.id);
          sets.push(s);
        }
        persist();
        notifyList();
        render();
        setStatus(`imported ${entries.length} set(s)`);
      } catch (e) {
        setStatus(`import failed: ${e.message}`);
      }
    };
    reader.readAsText(file);
  }

  /* ---------------- public ---------------- */

  function init(builtinSets, h) {
    serverSets = builtinSets || [];
    hooks = h || {};
    sets = merge(serverSets.map(setFromWire), readStored());
    selectedId = sets.length ? sets[0].id : null;
    if (sets.length) checked.add(sets[0].id);
    const base = sets.find((s) => s.id === "baseline");
    if (base) checked.add(base.id);
    persist();
    wireEvents();
    render();
  }

  function wireEvents() {
    const list = document.getElementById("setList");
    const editor = document.getElementById("setEditor");
    list.onclick = onListClick;
    list.onchange = onListClick;
    editor.oninput = onEditorInput;
    editor.onchange = onEditorInput;
    editor.onclick = onEditorClick;
    document.getElementById("newSet").onclick = () => newSet("blank");
    document.getElementById("duplicateSet").onclick = () => newSet("copy");
    document.getElementById("exportSets").onclick = exportSets;
    document.getElementById("restoreSets").onclick = restore;
    document.getElementById("importSets").onchange = (e) => e.target.files[0] && importSets(e.target.files[0]);
  }

  function wireFor(id) {
    const s = find(id);
    return s ? toWire(s.questions) : null;
  }

  function listSets() {
    return sets.map((s) => ({ id: s.id, name: s.name, count: s.questions.length, errors: validateSet(s).length }));
  }

  return { init, render, wireFor, listSets, toWire, questionsFromWire, validateSet, setFromWire, errorsFor };
})();

if (typeof module !== "undefined") module.exports = { Studio };
