/* kovra Web UI v2 (KOV-29) — client.
 *
 * No framework, no build. Drives the vendored Tabulator grid against the
 * governed `/api`. The server enforces all policy (policy::decide); this client
 * only ever renders what `/api` returns — it cannot show a value the server
 * withholds (I1/I2/I8). Modals are the native <dialog> element (no extra deps).
 */
"use strict";

const SESSION = new URLSearchParams(location.search).get("session") || "";
const H = { "x-kovra-session": SESSION };

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, html) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (html !== undefined) n.innerHTML = html;
  return n;
};
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

/** project name from an origin like `project:foo` (global → null). */
const projectOf = (origin) =>
  origin && origin.startsWith("project:") ? origin.slice(8) : null;

let table = null;

async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: { ...H, ...(opts.headers || {}) },
  });
  let body = null;
  try { body = await r.json(); } catch (_) { /* empty body */ }
  return { ok: r.ok, status: r.status, body };
}

/* ── toasts ───────────────────────────────────────────────────────────── */

function toast(msg, kind = "ok") {
  const t = el("div", { class: `toast ${kind}` }, esc(msg));
  $("#toasts").appendChild(t);
  setTimeout(() => t.classList.add("in"), 10);
  setTimeout(() => { t.classList.remove("in"); setTimeout(() => t.remove(), 250); }, 3200);
}

/* ── password/secret field with a Reveal (eye) toggle ─────────────────── */

const EYE = "👁";

/** A masked value field: <input type=password readonly> + Reveal + Copy. */
function secretFieldHtml(id, value) {
  return (
    `<div class="secret-field">` +
    `<input id="${id}" type="password" value="${esc(value)}" readonly autocomplete="off" spellcheck="false">` +
    `<button type="button" class="eye" data-target="${id}" title="Reveal">${EYE}</button>` +
    `<button type="button" class="copy" data-target="${id}" title="Copy">copy</button>` +
    `</div>`
  );
}

/** Wire the eye/copy buttons inside `root`. */
function wireSecretToggles(root) {
  root.querySelectorAll("button.eye").forEach((b) => {
    b.onclick = () => {
      const inp = root.querySelector(`#${b.dataset.target}`);
      const masked = inp.type === "password";
      inp.type = masked ? "text" : "password";
      b.classList.toggle("on", masked);
      b.title = masked ? "Hide" : "Reveal";
    };
  });
  root.querySelectorAll("button.copy").forEach((b) => {
    b.onclick = async () => {
      const inp = root.querySelector(`#${b.dataset.target}`);
      try { await navigator.clipboard.writeText(inp.value); toast("copied"); }
      catch (_) { toast("copy failed", "err"); }
    };
  });
}

/* ── governed reveal dialog ───────────────────────────────────────────── */

function row(k, v) {
  return `<div class="row"><span class="k">${esc(k)}</span> ${v}</div>`;
}

function badge(sensitivity) {
  const s = esc(sensitivity || "");
  return `<span class="badge ${s}">${s}</span>`;
}

function renderReveal(j) {
  // Literal value actually returned (low/medium only — the server's I1/I2 gate).
  // Shown in a masked password field with a Reveal (eye) toggle.
  if (j.value !== undefined) {
    return {
      title: "Revealed value",
      html:
        row("Coordinate", `<code>${esc(j.coordinate)}</code>`) +
        row("Sensitivity", badge(j.sensitivity)) +
        `<div class="row"><span class="k">Value</span></div>` +
        secretFieldHtml("reveal-value", j.value),
    };
  }
  if (j.masked) {
    return {
      title: "Masked (critical)",
      html:
        row("Coordinate", `<code>${esc(j.coordinate)}</code>`) +
        (j.sensitivity ? row("Sensitivity", badge(j.sensitivity)) : "") +
        (j.fingerprint ? row("Fingerprint", `<span class="fp">${esc(j.fingerprint)}</span>`) : "") +
        `<p class="note"><span class="lock">🔒 masked in the browser.</span> ${esc(j.note || "")}</p>`,
    };
  }
  if (j.inject_only) {
    return {
      title: "Inject-only",
      html:
        row("Coordinate", `<code>${esc(j.coordinate)}</code>`) +
        row("Sensitivity", badge(j.sensitivity)) +
        `<p class="note"><span class="lock">🔒 never revealed on any surface (I2).</span></p>`,
    };
  }
  if (j.kind === "reference") {
    return {
      title: "Reference",
      html:
        row("Coordinate", `<code>${esc(j.coordinate)}</code>`) +
        row("Pointer", `<code>${esc(j.pointer)}</code>`) +
        row("Status", esc(j.status || "")) +
        `<p class="note">${esc(j.note || "")}</p>`,
    };
  }
  if (j.kind === "keypair" || j.kind === "public-only") {
    return {
      title: j.kind === "keypair" ? "Keypair" : "Public key",
      html:
        row("Coordinate", `<code>${esc(j.coordinate)}</code>`) +
        row("Algorithm", esc(j.algorithm || "")) +
        `<div class="row"><span class="k">Public key</span></div>` +
        `<div class="value">${esc(j.public || "")}</div>` +
        `<p class="note">${esc(j.note || "")}</p>`,
    };
  }
  if (j.kind === "totp") {
    return {
      title: "TOTP enrollment",
      html:
        row("Coordinate", `<code>${esc(j.coordinate)}</code>`) +
        row("Algorithm", esc(j.algorithm || "")) +
        row("Digits", esc(j.digits)) +
        row("Period", `${esc(j.period)}s`) +
        `<p class="note">${esc(j.note || "")}</p>`,
    };
  }
  return {
    title: "Details",
    html:
      row("Coordinate", `<code>${esc(j.coordinate || "")}</code>`) +
      `<p class="note">${esc(j.note || JSON.stringify(j))}</p>`,
  };
}

/** Slide the reveal drawer in (with scrim). */
function openReveal() {
  $("#drawer").classList.add("show");
  $("#scrim").classList.add("show");
}
/** Close the reveal drawer (and scrim). */
function closeReveal() {
  $("#drawer").classList.remove("show");
  $("#scrim").classList.remove("show");
}

async function inspect(d) {
  const q = new URLSearchParams({ coord: d.coordinate });
  const p = projectOf(d.origin);
  if (p) q.set("project", p);
  const { ok, status, body } = await api(`/api/reveal?${q}`);
  const bodyEl = $("#reveal-body");
  if (!ok) {
    $("#reveal-title").textContent = "Error";
    bodyEl.innerHTML = `<p class="note">request failed (${status})</p>`;
  } else {
    const { title, html } = renderReveal(body);
    $("#reveal-title").textContent = title;
    bodyEl.innerHTML = html;
    wireSecretToggles(bodyEl);
  }
  openReveal();
}

/* ── form dialog (create / generate / edit / delete) ──────────────────── */

const SENS = ["low", "medium", "high", "inject-only"];

const field = (label, inner) =>
  `<label class="field"><span class="lbl">${esc(label)}</span>${inner}</label>`;
const sensSelect = (id, sel = "medium") =>
  `<select id="${id}">` +
  SENS.map((s) => `<option value="${s}"${s === sel ? " selected" : ""}>${s}</option>`).join("") +
  `</select>`;

let onSubmit = null; // the active form's submit handler

function openForm(title, bodyHtml, submit, submitLabel = "Save", danger = false) {
  $("#form-title").textContent = title;
  const body = $("#form-body");
  body.innerHTML = bodyHtml;
  wireSecretToggles(body);
  const btn = $("#form-submit");
  btn.textContent = submitLabel;
  btn.classList.toggle("danger", danger);
  btn.disabled = false; // a gated form (e.g. type-to-confirm delete) may re-disable it
  onSubmit = submit;
  $("#form").showModal();
  const first = body.querySelector("input,select,textarea");
  if (first) first.focus();
}

function openCreate() {
  const html =
    field("Coordinate", `<input id="f-coord" placeholder="dev/db/password" autocomplete="off">`) +
    `<div class="field"><span class="lbl">Kind</span><div class="radios">` +
    `<label><input type="radio" name="kind" value="literal" checked> Literal value</label>` +
    `<label><input type="radio" name="kind" value="reference"> Reference</label>` +
    `<label><input type="radio" name="kind" value="generate"> Generate</label>` +
    `</div></div>` +
    `<div id="f-literal">${field("Value", secretFieldHtml("f-value", ""))}</div>` +
    `<div id="f-reference" hidden>${field("Pointer", `<input id="f-pointer" placeholder="azure-kv://vault/name" autocomplete="off">`)}</div>` +
    `<div id="f-generate" hidden>${field("Length", `<input id="f-length" type="number" value="32" min="1" max="256">`)}</div>` +
    field("Sensitivity", sensSelect("f-sens")) +
    field("Description", `<input id="f-desc" autocomplete="off">`) +
    `<label class="field check"><input id="f-reveal" type="checkbox"> revealable over MCP (non-prod, non-high only)</label>`;

  openForm("New secret", html, async () => {
    const coord = $("#f-coord").value.trim();
    if (!coord) { toast("coordinate is required", "err"); return false; }
    const kind = $("#form-body").querySelector("input[name=kind]:checked").value;
    const sensitivity = $("#f-sens").value;
    const description = $("#f-desc").value.trim() || undefined;
    if (kind === "generate") {
      const length = parseInt($("#f-length").value, 10) || 32;
      return submitJson("POST", "/api/generate", { coord, length, sensitivity, description }, "generated");
    }
    const revealable = $("#f-reveal").checked;
    const payload = { coord, sensitivity, description, revealable };
    if (kind === "reference") payload.reference = $("#f-pointer").value.trim();
    else payload.value = $("#f-value").value;
    return submitJson("POST", "/api/secret", payload, "created");
  });

  // kind toggles which extra field shows.
  const body = $("#form-body");
  body.querySelectorAll("input[name=kind]").forEach((r) => {
    r.onchange = () => {
      const k = body.querySelector("input[name=kind]:checked").value;
      $("#f-literal").hidden = k !== "literal";
      $("#f-reference").hidden = k !== "reference";
      $("#f-generate").hidden = k !== "generate";
    };
  });
}

function openEdit(d) {
  const isRef = d.mode === "reference";
  const isLiteral = d.mode === "literal";
  const html =
    `<p class="note">Editing <code>${esc(d.coordinate)}</code></p>` +
    field("Sensitivity", sensSelect("e-sens", d.sensitivity)) +
    field("Description", `<input id="e-desc" autocomplete="off" value="${esc(d.description || "")}">`) +
    (isRef ? field("Pointer", `<input id="e-pointer" autocomplete="off" value="${esc(d.pointer || "")}">`) : "") +
    (isLiteral ? `<div class="field"><span class="lbl">New value <span class="muted">(optional)</span></span>${secretFieldHtml("e-value", "")}</div>` : "") +
    `<label class="field check"><input id="e-reveal" type="checkbox"${d.revealable ? " checked" : ""}> revealable over MCP</label>`;

  openForm(`Edit ${d.coordinate}`, html, async () => {
    const p = projectOf(d.origin);
    const meta = {
      coord: d.coordinate,
      project: p || undefined,
      sensitivity: $("#e-sens").value,
      description: $("#e-desc").value.trim() || undefined,
      revealable: $("#e-reveal").checked,
    };
    if (isRef) meta.reference = $("#e-pointer").value.trim();
    const r1 = await api("/api/secret", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(meta),
    });
    if (!r1.ok) { toast(r1.body?.error || `edit failed (${r1.status})`, "err"); return false; }
    // Optional value replacement for literals.
    const newVal = isLiteral ? $("#e-value").value : "";
    if (newVal) {
      const r2 = await api("/api/secret", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ coord: d.coordinate, project: p || undefined, value: newVal }),
      });
      if (!r2.ok) { toast(r2.body?.error || `value update failed (${r2.status})`, "err"); return false; }
    }
    toast("saved");
    return true;
  });
}

function openDelete(d) {
  // The delete gate mirrors the reveal tier (KOV-30): critical secrets (high /
  // inject-only) are confirmed at the broker (Touch ID / `kovra approve`) — the
  // server enforces it. Non-critical secrets (low / medium) are not biometric-
  // gated; we guard them here with a type-the-name confirmation against
  // accidental deletion.
  const critical = d.sensitivity === "high" || d.sensitivity === "inject-only";
  const doDelete = async () => {
    const p = projectOf(d.origin);
    const q = new URLSearchParams({ coord: d.coordinate });
    if (p) q.set("project", p);
    const { ok, status, body } = await api(`/api/secret?${q}`, { method: "DELETE" });
    if (!ok) { toast(body?.error || `delete failed (${status})`, "err"); return false; }
    toast("deleted");
    return true;
  };

  if (critical) {
    const html =
      `<p>Delete <code>${esc(d.coordinate)}</code> (<strong>${esc(d.sensitivity)}</strong>)? This cannot be undone.</p>` +
      `<p class="note">You'll be asked to approve on your device (Touch ID), or via <code>kovra approve</code> in a terminal.</p>`;
    openForm("Delete secret", html, doDelete, "Delete", true);
    return;
  }

  const html =
    `<p>Delete <code>${esc(d.coordinate)}</code>? This cannot be undone.</p>` +
    // The coordinate is shown read-only with a Copy button (reusing the secret-
    // field affordance) so the confirmation can be copy-pasted, not retyped.
    `<label class="field"><span class="lbl">Coordinate</span>` +
    `<div class="secret-field">` +
    `<input id="del-name" type="text" value="${esc(d.coordinate)}" readonly autocomplete="off" spellcheck="false">` +
    `<button type="button" class="copy" data-target="del-name" title="Copy">copy</button>` +
    `</div></label>` +
    `<label class="field"><span class="lbl">Type or paste it to confirm</span>` +
    `<input id="del-confirm" autocomplete="off" placeholder="${esc(d.coordinate)}"></label>`;
  openForm("Delete secret", html, async () => {
    if ($("#del-confirm").value.trim() !== d.coordinate) {
      toast("name does not match", "err");
      return false;
    }
    return doDelete();
  }, "Delete", true);

  // Selecting the read-only coordinate (click or double-click) selects it whole,
  // so it can be copied with Ctrl-C and pasted (Ctrl-V) into the field below —
  // in addition to the Copy button.
  const name = $("#del-name");
  name.onfocus = () => name.select();
  name.onclick = () => name.select();

  // Keep the danger button disabled until the confirmation matches exactly.
  const inp = $("#del-confirm");
  const btn = $("#form-submit");
  btn.disabled = true;
  inp.oninput = () => { btn.disabled = inp.value.trim() !== d.coordinate; };
  inp.focus(); // the read-only coordinate is first in the DOM; focus the input to fill
}

/** POST/PUT a JSON body; on success toast + signal the form to close + reload. */
async function submitJson(method, path, payload, okWord) {
  const { ok, status, body } = await api(path, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!ok) { toast(body?.error || `${okWord} failed (${status})`, "err"); return false; }
  toast(okWord);
  return true;
}

/* ── grid (flat table ↔ coordinate tree) ──────────────────────────────── */

let view = "table"; // "table" | "tree" | "projects"
let currentSecrets = [];
let searchTerm = "";          // from the topbar search box
const colFilters = {};        // per-column popup filters: field → value
let selectedProject = null;   // origin selected in the Projects view ("global"|"project:x")

const isNode = (d) => !!(d && d._node);

function coordCell(cell) {
  const d = cell.getData();
  if (isNode(d)) {
    return `<strong>${esc(d._label)}</strong> <span class="muted">(${d._count})</span>`;
  }
  const shadow = d.shadows_global
    ? ' <span class="muted" title="shadows a global coordinate">*shadows global</span>'
    : "";
  // Only the env Tree nests rows under parents, so its leaves show just the key.
  // Table and Projects are flat lists → show the full coordinate.
  const label = view === "tree" ? esc(d.key) : esc(d.coordinate);
  return `<code>${label}</code>${shadow}`;
}
function modeCell(cell) {
  const d = cell.getData();
  if (isNode(d)) return "";
  const ptr = d.pointer ? ` <span class="muted">→ ${esc(d.pointer)}</span>` : "";
  return `<span class="mode-pill">${esc(d.mode || "")}</span>${ptr}`;
}
function fpCell(cell) {
  const d = cell.getData();
  if (isNode(d)) return "";
  return d.fingerprint ? `<span class="fp">${esc(d.fingerprint)}</span>` : "";
}
function sensCell(cell) {
  const d = cell.getData();
  return isNode(d) ? "" : badge(cell.getValue());
}
function actionCell(cell) {
  if (isNode(cell.getData())) return "";
  return (
    `<button class="row-act" data-act="inspect" title="Inspect / reveal">inspect</button>` +
    `<button class="row-act" data-act="edit" title="Edit">edit</button>` +
    `<button class="row-act danger" data-act="del" title="Delete">del</button>`
  );
}
function onAction(e, cell) {
  const act = e.target?.dataset?.act;
  if (!act) return; // a click on the node toggle / empty cell
  const d = cell.getData();
  if (act === "inspect") inspect(d);
  else if (act === "edit") openEdit(d);
  else if (act === "del") openDelete(d);
}

/** Nest the flat secrets list into env → component → secret (key) nodes. */
function toTree(secrets) {
  const envs = new Map();
  for (const s of secrets) {
    if (!envs.has(s.environment)) envs.set(s.environment, new Map());
    const comps = envs.get(s.environment);
    if (!comps.has(s.component)) comps.set(s.component, []);
    comps.get(s.component).push(s);
  }
  const out = [];
  for (const [env, comps] of envs) {
    let count = 0;
    const compNodes = [];
    for (const [comp, leaves] of comps) {
      count += leaves.length;
      compNodes.push({ _node: true, _label: comp, _count: leaves.length, coordinate: `${env}/${comp}`, _children: leaves });
    }
    out.push({ _node: true, _label: env, _count: count, coordinate: env, _children: compNodes });
  }
  return out;
}

/** project name from an origin (`project:foo` → `foo`, `global` → `global`). */
const originLabel = (origin) =>
  origin && origin.startsWith("project:") ? origin.slice(8) : "global";

const originOf = (s) => s.origin || "global";

/** Distinct origins in inventory order (global first, as the API lists it). */
function distinctOrigins(secrets) {
  const seen = new Set();
  const out = [];
  for (const s of secrets) {
    const o = originOf(s);
    if (!seen.has(o)) { seen.add(o); out.push(o); }
  }
  return out;
}

/** Render the project picker (chips) for the Projects view, and keep
 *  `selectedProject` valid. Selecting a chip re-renders the flat list (KOV-32). */
function renderProjectBar() {
  const bar = $("#project-bar");
  const origins = distinctOrigins(currentSecrets);
  if (selectedProject === null || !origins.includes(selectedProject)) {
    selectedProject = origins[0] || null;
  }
  bar.innerHTML = "";
  for (const o of origins) {
    const n = currentSecrets.filter((s) => originOf(s) === o).length;
    const chip = el(
      "button",
      { class: `proj-chip${o === selectedProject ? " on" : ""}`, "data-origin": o },
      `${esc(originLabel(o))} <span class="c">${n}</span>`,
    );
    chip.onclick = () => { selectedProject = o; render(); };
    bar.appendChild(chip);
  }
}

/* ── Excel-style column filters (funnel icon → popup) ─────────────────── */

const FUNNEL_ICON =
  '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 5h18l-7 8v5l-4 2v-7L3 5Z"/></svg>';

/** A row passes when it matches the global search AND every active column filter. */
function rowMatches(data) {
  if (isNode(data)) return true;
  if (searchTerm) {
    const hit = ["coordinate", "origin", "environment", "mode", "pointer"].some(
      (f) => String(data[f] || "").toLowerCase().includes(searchTerm),
    );
    if (!hit) return false;
  }
  for (const [field, val] of Object.entries(colFilters)) {
    if (!val) continue;
    if (field === "sensitivity") {
      if (String(data.sensitivity || "") !== val) return false;
    } else if (!String(data[field] || "").toLowerCase().includes(val.toLowerCase())) {
      return false;
    }
  }
  return true;
}

/** Recompute the single combined filter (search + all column popups). */
function applyFilters() {
  if (!table || view !== "table") return;
  const active = searchTerm || Object.values(colFilters).some(Boolean);
  if (active) table.setFilter(rowMatches);
  else table.clearFilter(true);
}

/** Highlight the funnel of every column that currently has an active filter. */
function markActiveFilterCols() {
  if (!table) return;
  for (const c of table.getColumns()) {
    const f = c.getField();
    c.getElement().classList.toggle("has-filter", !!(f && colFilters[f]));
  }
}

/** Build the popup body for a column filter (text input or sensitivity select). */
function filterPopup(field, kind) {
  return (e, column, onRendered) => {
    const wrap = el("div", { class: "col-filter-popup" });
    wrap.appendChild(el("div", { class: "cfp-label" }, `Filter ${esc(column.getDefinition().title)}`));
    const input =
      kind === "sens"
        ? el("select", { class: "cfp-input" },
            `<option value="">all</option>` + SENS.map((s) => `<option value="${s}">${s}</option>`).join(""))
        : el("input", { class: "cfp-input", type: "text", placeholder: "contains…", autocomplete: "off" });
    input.value = colFilters[field] || "";
    const onChange = () => {
      const v = (input.value || "").trim();
      if (v) colFilters[field] = v;
      else delete colFilters[field];
      column.getElement().classList.toggle("has-filter", !!v);
      applyFilters();
    };
    input.addEventListener("input", onChange);
    input.addEventListener("change", onChange);
    wrap.appendChild(input);
    const clear = el("button", { type: "button", class: "cfp-clear" }, "Clear");
    clear.addEventListener("click", () => { input.value = ""; onChange(); input.focus(); });
    wrap.appendChild(clear);
    onRendered(() => input.focus());
    return wrap;
  };
}

function columns() {
  // Column filters are popups in the flat table; the tree view has none.
  const pf = (field, kind) =>
    view === "table" ? { headerPopup: filterPopup(field, kind), headerPopupIcon: FUNNEL_ICON } : {};
  // minWidths fit "title + sort arrow + funnel button" so headers never truncate.
  return [
    { title: "Coordinate", field: "coordinate", formatter: coordCell, widthGrow: 3, minWidth: 220, ...pf("coordinate", "text") },
    { title: "Origin", field: "origin", widthGrow: 1, minWidth: 120, ...pf("origin", "text") },
    { title: "Env", field: "environment", width: 120, minWidth: 120, ...pf("environment", "text") },
    { title: "Sensitivity", field: "sensitivity", width: 175, minWidth: 175, formatter: sensCell, ...pf("sensitivity", "sens") },
    { title: "Mode", field: "mode", formatter: modeCell, widthGrow: 2, minWidth: 150, ...pf("mode", "text") },
    { title: "Fingerprint", field: "fingerprint", width: 150, minWidth: 130, formatter: fpCell },
    { title: "", field: "_act", width: 210, minWidth: 210, hozAlign: "right", headerSort: false, formatter: actionCell, cellClick: onAction },
  ];
}

/** Double-clicking a secret row opens its inspect/reveal drawer (not on tree
 *  nodes, and not when the click lands on a row-action button). */
function onRowDblClick(e, row) {
  if (e.target?.closest && e.target.closest("button.row-act")) return;
  const d = row.getData();
  if (!isNode(d)) inspect(d);
}

function render() {
  if (table) { table.destroy(); table = null; }
  const common = {
    layout: "fitColumns", height: "100%", movableColumns: true, placeholder: "no secrets",
    columns: columns(), rowDblClick: onRowDblClick,
    // Reapply persisted filters after the grid (re)builds — e.g. after a refresh.
    tableBuilt() { applyFilters(); markActiveFilterCols(); },
  };
  // The project picker is shown only in the Projects view.
  const bar = $("#project-bar");
  if (bar) bar.hidden = view !== "projects";

  if (view === "tree") {
    table = new Tabulator("#grid", {
      ...common,
      data: toTree(currentSecrets),
      dataTree: true,
      dataTreeStartExpanded: true,
      dataTreeElementColumn: "coordinate",
    });
  } else {
    // Table = all secrets, flat. Projects = pick a project, then its secrets as
    // a flat list (KOV-32 — a list once selected, not a tree).
    let data = currentSecrets;
    if (view === "projects") {
      renderProjectBar();
      data = currentSecrets.filter((s) => originOf(s) === selectedProject);
    }
    table = new Tabulator("#grid", {
      ...common,
      data,
      pagination: true,
      paginationSize: 25,
      paginationSizeSelector: [10, 25, 50, 100],
      initialSort: [{ column: "coordinate", dir: "asc" }],
    });
  }
}

function setView(v) {
  if (view === v) return;
  view = v;
  $("#view-table").classList.toggle("on", v === "table");
  $("#view-tree").classList.toggle("on", v === "tree");
  $("#view-projects").classList.toggle("on", v === "projects");
  // Switching views resets the active filters (search + column popups).
  $("#search").value = "";
  searchTerm = "";
  Object.keys(colFilters).forEach((k) => delete colFilters[k]);
  render();
}

/** Global search across the human-relevant fields (flat table only). */
function applySearch(term) {
  searchTerm = (term || "").trim().toLowerCase();
  applyFilters();
}

/** Recompute the header subtitle count + the stats strip from the inventory. */
function updateStats() {
  const n = currentSecrets.length;
  const count = (pred) => currentSecrets.filter(pred).length;
  $("#status").textContent = `${n} secret${n === 1 ? "" : "s"}`;
  $("#stat-total").textContent = n;
  $("#stat-high").textContent = count((s) => s.sensitivity === "high");
  $("#stat-inject").textContent = count((s) => s.sensitivity === "inject-only");
  $("#stat-ref").textContent = count((s) => s.mode === "reference");
}

async function load() {
  const { ok, status: code, body } = await api("/api/secrets");
  if (!ok) { $("#status").textContent = `auth error (${code})`; return; }
  currentSecrets = body.secrets || [];
  render();
  updateStats();
}

/* ── theme (persisted) ────────────────────────────────────────────────── */

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("kovra-theme", t); } catch (_) { /* private mode */ }
}
function toggleTheme() {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
}

document.addEventListener("DOMContentLoaded", () => {
  try {
    const saved = localStorage.getItem("kovra-theme");
    if (saved) applyTheme(saved);
  } catch (_) { /* private mode */ }

  $("#search").addEventListener("input", (e) => applySearch(e.target.value));
  $("#refresh").addEventListener("click", load);
  $("#theme").addEventListener("click", toggleTheme);
  $("#new").addEventListener("click", openCreate);
  $("#view-table").addEventListener("click", () => setView("table"));
  $("#view-tree").addEventListener("click", () => setView("tree"));
  $("#view-projects").addEventListener("click", () => setView("projects"));
  $("#reveal-close").addEventListener("click", closeReveal);
  $("#scrim").addEventListener("click", closeReveal);
  $("#form-cancel").addEventListener("click", () => $("#form").close());
  $("#form-cancel-2").addEventListener("click", () => $("#form").close());
  $("#form-el").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!onSubmit) return;
    const ok = await onSubmit();
    if (ok) { $("#form").close(); load(); }
  });
  load();
});
