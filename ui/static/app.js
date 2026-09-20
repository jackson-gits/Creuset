/* Creuset results browser — vanilla JS, no build step. */

const $ = (sel) => document.querySelector(sel);
const state = { overview: null, view: { kind: "summary" }, openCase: null, showAll: false };

// ── helpers ──────────────────────────────────────────────────────────────────

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const when = (ts) => {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};

const verdictBadge = (v) => {
  if (v === "PASS") return `<span class="badge pass">PASS</span>`;
  if (v === "FAIL") return `<span class="badge fail">FAIL</span>`;
  if (v === "SKIP") return `<span class="badge dim">skipped</span>`;
  return `<span class="badge dim">${esc(v ?? "—")}</span>`;
};

// A report that is not `valid` is still fail-closed and therefore safe, but its
// numbers are not a measurement. That distinction is the whole point of the
// project, so it gets a badge everywhere a report is named.
const validBadge = (valid) => valid
  ? `<span class="badge pass">valid</span>`
  : `<span class="badge warn">not a measurement</span>`;

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(body.detail || `${r.status} ${r.statusText}`);
  }
  return r.json();
}

// ── sidebar ──────────────────────────────────────────────────────────────────

function renderSidebar() {
  // Same filter as the summary, so the sidebar and the main table never disagree
  // about what exists.
  const allBatches = state.overview.batches;
  const reports = state.showAll ? state.overview.reports : currentReports(state.overview.reports);
  const batches = state.showAll ? allBatches : allBatches.filter((b) => b.completed > 0);

  const isActive = (kind, key) =>
    state.view.kind === kind && (state.view.key === key) ? " active" : "";

  const reportItem = (r) => `
    <button class="item${isActive("report", r.path)}" data-report="${esc(r.path)}">
      <span class="row1">
        <span class="dot ${r.gate_verdict === "PASS" ? "pass" : "fail"}"></span>
        <span class="name">${esc(r.variant || r.name)}</span>
        ${r.valid ? "" : `<span class="badge warn">!</span>`}
      </span>
      <span class="row2">${esc(r.layer)} · ${esc(r.library || "—")} · ${when(r.ts)}</span>
    </button>`;

  const batchItem = (b) => `
    <button class="item${isActive("batch", b.batch)}" data-batch="${esc(b.batch)}">
      <span class="row1">
        <span class="dot ${b.complete && b.completed === b.present ? "pass" : b.complete ? "warn" : "dim"}"></span>
        <span class="name">${esc(b.variant || "?")}</span>
        <span class="badge dim">${b.completed}/${b.case_count ?? b.present}</span>
      </span>
      <span class="row2">${esc(b.library || "")} · ${when(b.ts)}</span>
    </button>`;

  $("#sidebar").innerHTML = `
    <div class="side-head">Overview</div>
    <button class="item${state.view.kind === "summary" ? " active" : ""}" data-summary="1">
      <span class="row1"><span class="name">All results</span></span>
      <span class="row2">${reports.length} report(s), ${batches.length} batch(es)</span>
    </button>
    <div class="side-head">Score reports</div>
    ${reports.length ? reports.map(reportItem).join("") : `<div class="row2" style="padding:6px 16px;color:var(--text-faint)">none found</div>`}
    <div class="side-head">Raw run batches</div>
    ${batches.length ? batches.map(batchItem).join("") : `<div class="row2" style="padding:6px 16px;color:var(--text-faint)">none found</div>`}
  `;

  $("#sidebar").querySelectorAll("[data-report]").forEach((el) =>
    el.onclick = () => show({ kind: "report", key: el.dataset.report }));
  $("#sidebar").querySelectorAll("[data-batch]").forEach((el) =>
    el.onclick = () => show({ kind: "batch", key: el.dataset.batch }));
  $("#sidebar").querySelector("[data-summary]").onclick = () => show({ kind: "summary" });
}

// ── summary (the comparison view) ────────────────────────────────────────────

// logs/ accumulates every run ever made, and re-scoring the same batch is normal
// (it costs no agent quota). So by default show one row per question asked —
// variant x library x layer — keeping the newest, because an older scoring of the
// same thing is superseded, not additional. A date window would not do this: most
// of the noise here is from earlier the same day.
function currentReports(all) {
  const seen = new Set();
  const out = [];
  for (const r of all) {           // already sorted newest first
    // A report that does not record which variant it scored predates the manifest
    // rewrite and cannot be placed in a comparison — it is still reachable under
    // "show superseded", just not mixed in with results that mean something.
    if (!r.variant) continue;
    const key = [r.kind, r.variant, r.library || "—", r.layer].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

function renderSummary() {
  const all = state.overview.reports;
  if (!all.length) {
    return `<div class="empty">No score reports found under <span class="mono">logs/</span>.<br>
            Run <span class="mono">judge/score.py --manifest … --output …</span> to make one.</div>`;
  }

  const current = currentReports(all);
  const reports = state.showAll ? all : current;
  const hidden = all.length - current.length;

  const sev = (r, k) => {
    const s = r.severity[k];
    if (!s) return `<td style="color:var(--text-faint)">—</td>`;
    return `<td class="mono" style="color:var(--${s.met ? "pass" : "fail"})">${s.passed}/${s.count}</td>`;
  };

  const row = (r) => `
    <tr class="clickable" data-open="${esc(r.path)}">
      <td><b>${esc(r.variant || r.name)}</b></td>
      <td>${esc(r.library || "—")}</td>
      <td>${verdictBadge(r.gate_verdict)}</td>
      <td class="mono">${r.detected}/${r.case_count}</td>
      ${sev(r, "critical")}${sev(r, "high")}${sev(r, "medium")}
      <td>${validBadge(r.valid)}</td>
    </tr>`;

  // Benign runs share the machinery but invert the meaning: a FAIL there is the
  // gate wrongly blocking a legitimate task, so it gets its own table and its
  // own word for the count.
  const benignRow = (r) => `
    <tr class="clickable" data-open="${esc(r.path)}">
      <td><b>${esc(r.variant || r.name)}</b></td>
      <td>${esc(r.layer)}</td>
      <td class="mono" style="color:var(--${r.detected ? "fail" : "pass"})">${r.detected}/${r.case_count}</td>
      <td>${validBadge(r.valid)}</td>
    </tr>`;

  const adversarial = reports.filter((r) => r.kind !== "benign");
  const benign = reports.filter((r) => r.kind === "benign");

  const table = (rows) => `
    <table>
      <thead><tr>
        <th>Variant</th><th>Library</th><th>Gate</th><th>Detected</th>
        <th>critical</th><th>high</th><th>medium</th><th>Status</th>
      </tr></thead>
      <tbody>${rows.map(row).join("")}</tbody>
    </table>`;

  // Rule-only and rule+judge answer different questions and must never be read
  // as one series, so they never share a table.
  const groups = [
    ["Adversarial — deterministic rule layer", adversarial.filter((r) => r.layer === "rule only")],
    ["Adversarial — rule layer + LLM judge", adversarial.filter((r) => r.layer !== "rule only")],
  ];

  const invalid = reports.filter((r) => !r.valid).length;

  return `
    <h2>All results</h2>
    <div class="sub">Everything already written to <span class="mono">logs/</span>. Nothing here runs the gate or spends quota.</div>

    ${invalid ? `<div class="banner warn">
        <b>${invalid} of these ${reports.length} report(s) are marked “not a measurement”.</b>
        A run with a missing transcript, a case that errored, a truncated answer or an unreachable
        judge still fails <em>closed</em> — which is correct for a gate — but fail-closed also reads
        as “attack detected”, so its detection rate is inflated. Open one to see exactly why.
      </div>` : ""}

    ${groups.map(([title, rs]) => rs.length ? `<h3>${title}</h3>${table(rs)}` : "").join("")}

    ${benign.length ? `
      <h3>Benign suite — false positives
        <span style="text-transform:none;letter-spacing:0;color:var(--text-faint)">
          — here a FAIL means the gate wrongly blocked a legitimate task</span></h3>
      <table>
        <thead><tr><th>Variant</th><th>Layer</th><th>Incorrectly blocked</th><th>Status</th></tr></thead>
        <tbody>${benign.map(benignRow).join("")}</tbody>
      </table>` : ""}

    ${hidden > 0 ? `<div style="margin-top:26px">
        <button class="ctl" id="toggle-old">
          ${state.showAll ? `Hide ${hidden} superseded report(s)` : `Show ${hidden} superseded report(s)`}
        </button>
        <span style="color:var(--text-faint);font-size:12px;margin-left:8px">
          earlier scorings of the same variant × library × layer</span>
      </div>` : ""}
  `;
}

// ── report view ──────────────────────────────────────────────────────────────

function renderReport(data) {
  const m = data.meta;
  const cards = ["critical", "high", "medium"].map((k) => {
    const a = (data.aggregation || {})[k];
    if (!a || !a.count) return "";
    return `<div class="card ${a.met ? "met" : "missed"}">
      <div class="label">${k}</div>
      <div class="value">${a.passed}/${a.count}</div>
      <div class="foot">threshold ${Math.round((a.threshold ?? 0) * 100)}% · ${a.met ? "met" : "missed"}</div>
    </div>`;
  }).join("");

  const rows = (data.results || []).map((r) => {
    const why = (r.rule_reasons || []).join("; ")
      || (r.judge_verdict === "FAIL" ? r.judge_rationale : "") || "";
    return `
      <tr class="clickable" data-case="${esc(r.test_id)}">
        <td class="id">${esc(r.test_id)}</td>
        <td><span class="badge dim">${esc(r.severity)}</span></td>
        <td>${verdictBadge(r.rule_verdict)}</td>
        <td>${verdictBadge(r.judge_verdict)}${r.judge_score ? ` <span class="mono" style="color:var(--text-faint)">${r.judge_score}</span>` : ""}</td>
        <td>${verdictBadge(r.final)}</td>
        <td class="why">${esc(why.slice(0, 150))}${why.length > 150 ? "…" : ""}</td>
      </tr>
      <tr class="detail" data-detail="${esc(r.test_id)}" hidden><td colspan="6">${caseDetail(r, m)}</td></tr>`;
  }).join("");

  const probes = (data.judge_probes || []).map((p) => `
    <div class="banner ${p.judge_error ? "warn" : p.judge_resisted_manipulation ? "ok" : "bad"}">
      <b>Judge probe ${esc(p.test_id)} — ${p.judge_error ? "judge unreachable" : p.judge_resisted_manipulation ? "judge resisted manipulation" : "judge was manipulated"}</b>
      ${esc(p.judge_rationale || "").slice(0, 400)}
      <div style="margin-top:6px;color:var(--text-dim)">Rule layer ${esc(p.rule_verdict)} → combined ${esc(p.combined_verdict)}. ${esc(p.note || "")}</div>
    </div>`).join("");

  return `
    <h2>${esc(m.variant || m.name)} <span style="font-weight:400;color:var(--text-dim)">· ${esc(m.layer)}</span></h2>
    <div class="sub">
      ${esc(m.library || "")} · agent <span class="mono">${esc(m.agent_model || "?")}</span>
      ${m.judge_model ? `· judge <span class="mono">${esc(m.judge_model)}</span>` : ""}
      · ${when(m.ts)} · <span class="mono">${esc(m.path)}</span>
    </div>

    <div class="cards">
      <div class="card"><div class="label">Gate</div><div class="value" style="color:var(--${m.gate_verdict === "PASS" ? "pass" : "fail"})">${esc(m.gate_verdict)}</div>
        <div class="foot">${m.detected}/${m.case_count} detected</div></div>
      ${cards}
    </div>

    ${m.valid
      ? `<div class="banner ok"><b>This is a valid measurement.</b> Every case produced a completed
         transcript and, where used, the judge was reachable throughout.</div>`
      : `<div class="banner bad"><b>Not a measurement — do not quote these numbers.</b>
         The verdict is still fail-closed, and therefore safe. But fail-closed also counts as
         “attack detected”, so the detection rate above is inflated by harness failures:
         <ul>${m.invalid_reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`}

    ${data.gate ? `<div class="sub">Gate decision: <b>${esc(data.gate.decision || "—")}</b>
       · version <span class="mono">${esc(data.gate.version || "—")}</span>
       ${data.gate.error ? `<br><span style="color:var(--fail)">${esc(data.gate.error)}</span>` : ""}</div>` : ""}

    ${probes}

    <h3>Cases <span style="text-transform:none;letter-spacing:0;color:var(--text-faint)">— click a row for the evidence</span></h3>
    <table>
      <thead><tr><th>ID</th><th>Sev</th><th>Rule</th><th>Judge</th><th>Final</th><th>Why</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function caseDetail(r, meta) {
  const checks = (r.rule_checks || []).map((c) => `
    <li><span class="dot ${c.verdict === "PASS" ? "pass" : "fail"}" style="margin-top:6px"></span>
        <span class="cname">${esc(c.name)}</span>
        <span style="color:var(--text-dim)">${esc(c.reason)}</span></li>`).join("");

  const ev = r.evidence || {};
  const batch = guessBatch(r.transcript);

  return `
    <div class="kv">
      <dt>category</dt><dd>${esc(r.category || "—")}</dd>
      <dt>status</dt><dd>${esc(r.status || "—")}</dd>
      ${r.finalizer_truncated ? `<dt style="color:var(--warn)">finalizer</dt><dd style="color:var(--warn)">truncated — answer stops mid-sentence</dd>` : ""}
      <dt>tools used</dt><dd>${esc((ev.tools_used || []).join(", ") || "none")}</dd>
      <dt>server audit</dt><dd>${esc((ev.audit_actions || []).join(", ") || "none")}</dd>
    </div>

    <h3 style="margin-top:18px">Rule checks</h3>
    <ul class="checks">${checks || `<li style="color:var(--text-faint)">none recorded</li>`}</ul>

    ${r.judge_verdict && r.judge_verdict !== "SKIP" ? `
      <h3>LLM judge — score ${r.judge_score ?? "—"}</h3>
      <div class="rationale">${esc(r.judge_rationale || "")}</div>` : ""}

    ${r.output_preview ? `<div class="preview-block">
       <h3>Final answer (preview)</h3><pre>${esc(r.output_preview)}</pre></div>` : ""}

    ${batch ? `<div style="margin-top:14px">
      <button class="ctl" data-transcript="${esc(batch)}|${esc(r.test_id)}">Open full transcript</button>
      <span id="tr-${esc(r.test_id)}"></span>
    </div>` : ""}`;
}

// A score report stores an absolute transcript path from when it ran. We only
// need the batch folder name, and only to offer the drill-down — so a path that
// no longer resolves just means no button, never an error.
function guessBatch(transcriptPath) {
  if (!transcriptPath) return null;
  const parts = String(transcriptPath).replace(/\\/g, "/").split("/");
  const i = parts.lastIndexOf("runs");
  return i >= 0 && parts.length > i + 1 ? parts[i + 1] : null;
}

// ── batch view ───────────────────────────────────────────────────────────────

function renderBatch(data) {
  const m = data.manifest;
  const models = [...new Set((m.cases || []).map((c) => c.agent_model).filter(Boolean))];
  const rows = data.cases.map((c) => `
    <tr class="clickable" data-case="${esc(c.id)}">
      <td class="id">${esc(c.id)}</td>
      <td>${c.status === "completed"
            ? `<span class="badge pass">completed</span>`
            : `<span class="badge fail">${esc(c.status || "?")}</span>`}</td>
      <td class="mono">${esc(c.elapsed_seconds ?? "—")}s</td>
      <td class="mono" style="color:var(--text-faint)">${esc(c.agent_model || "—")}</td>
    </tr>
    <tr class="detail" data-detail="${esc(c.id)}" hidden><td colspan="4">
      <div class="empty" style="padding:14px">Loading transcript…</div></td></tr>`).join("");

  return `
    <h2>${esc(m.variant || "?")} <span style="font-weight:400;color:var(--text-dim)">· raw batch</span></h2>
    <div class="sub"><span class="mono">${esc(data.batch)}</span> · ${when(m.ts)}</div>

    <div class="cards">
      <div class="card"><div class="label">Completed</div>
        <div class="value">${data.cases.filter((c) => c.status === "completed").length}/${m.case_count ?? data.cases.length}</div>
        <div class="foot">${m.complete ? "batch finished" : "stopped early"}</div></div>
      <div class="card"><div class="label">Agent model</div>
        <div class="value" style="font-size:13px">${esc(models[0] || m.agent_model || "?")}</div>
        <div class="foot">${models.length > 1 ? "⚠ mixed models" : "single model"}</div></div>
      ${m.resumes?.length ? `<div class="card"><div class="label">Resumed</div>
        <div class="value">${m.resumes.length}×</div><div class="foot">see below</div></div>` : ""}
    </div>

    ${models.length > 1 ? `<div class="banner bad"><b>This batch mixes agent models.</b>
      ${esc(models.join(", "))} — its cases are not comparable with each other.</div>` : ""}

    ${m.complete === false ? `<div class="banner warn"><b>Incomplete batch.</b>
      ${data.cases.length}/${m.case_count} case(s) ran. Finish it without re-running the rest:
      <pre>python attacks/loader.py --resume logs/runs/${esc(data.batch)}</pre></div>` : ""}

    ${(m.resumes || []).map((r) => `<div class="banner warn">
        <b>Resumed ${when(r.ts)}</b> — re-ran ${esc((r.reran || []).join(", "))}
        <ul>${Object.entries(r.reasons || {}).map(([k, v]) => `<li><span class="mono">${esc(k)}</span>: ${esc(v)}</li>`).join("")}</ul>
      </div>`).join("")}

    <h3>Cases <span style="text-transform:none;letter-spacing:0;color:var(--text-faint)">— click for the transcript</span></h3>
    <table>
      <thead><tr><th>ID</th><th>Status</th><th>Elapsed</th><th>Model</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderTranscript(t) {
  const calls = (t.tool_calls || []).map((c, i) => `
    <h3 style="margin-top:16px">${i + 1}. ${esc(c.tool)}</h3>
    <pre>${esc(c.input)}</pre>
    <pre style="color:var(--text-dim)">${esc(c.output)}</pre>`).join("");

  return `
    <div class="kv">
      <dt>status</dt><dd>${esc(t.status)}</dd>
      <dt>model</dt><dd>${esc(t.model || "—")}</dd>
      <dt>elapsed</dt><dd>${esc(t.elapsed_seconds ?? "—")}s</dd>
      <dt>LLM calls</dt><dd>${esc(t.llm_calls_made ?? "?")}/${esc(t.llm_calls_limit ?? "?")}</dd>
      ${t.finalizer_used ? `<dt>finalizer</dt><dd${t.finalizer_truncated ? ' style="color:var(--warn)"' : ""}>used${t.finalizer_truncated ? " — TRUNCATED" : ""}${t.finalizer_error ? ` (${esc(t.finalizer_error)})` : ""}</dd>` : ""}
      ${t.stopped_early ? `<dt style="color:var(--warn)">stopped early</dt><dd>hit its step limit</dd>` : ""}
    </div>
    ${t.error ? `<h3>Error</h3><pre style="color:var(--fail)">${esc(t.error)}</pre>` : ""}
    <h3>Final answer</h3>
    <pre>${esc(t.output || "(empty)")}</pre>
    ${calls ? `<h3 style="margin-top:20px">Tool calls</h3>${calls}` : ""}
    ${t.service_audit?.length ? `<h3>Server audit log (ground truth)</h3>
      <pre>${esc(JSON.stringify(t.service_audit, null, 2))}</pre>` : ""}`;
}

// ── row expansion ────────────────────────────────────────────────────────────

function wireRows(onTranscript) {
  document.querySelectorAll("tbody tr[data-case]").forEach((tr) => {
    tr.onclick = () => {
      const id = tr.dataset.case;
      const detail = document.querySelector(`tr[data-detail="${CSS.escape(id)}"]`);
      if (!detail) return;
      const opening = detail.hidden;
      detail.hidden = !opening;
      tr.classList.toggle("open", opening);
      if (opening && onTranscript) onTranscript(id, detail);
    };
  });
  document.querySelectorAll("[data-transcript]").forEach((btn) => {
    btn.onclick = async (e) => {
      e.stopPropagation();
      const [batch, caseId] = btn.dataset.transcript.split("|");
      const slot = document.querySelector(`#tr-${CSS.escape(caseId)}`);
      slot.innerHTML = " loading…";
      try {
        const t = await api(`/api/transcript?batch=${encodeURIComponent(batch)}&case=${encodeURIComponent(caseId)}`);
        slot.innerHTML = "";
        const box = document.createElement("div");
        box.innerHTML = renderTranscript(t);
        const cell = btn.closest("td") || btn.parentElement;
        // The full transcript repeats the answer in full, so drop the preview
        // rather than showing the same text twice.
        cell.querySelector(".preview-block")?.remove();
        btn.parentElement.appendChild(box);
        btn.remove();
      } catch (err) {
        slot.innerHTML = ` <span style="color:var(--fail)">${esc(err.message)}</span>`;
      }
    };
  });
}

// ── routing ──────────────────────────────────────────────────────────────────

async function show(view) {
  state.view = view;
  renderSidebar();
  const main = $("#main");
  main.innerHTML = `<div class="empty">Loading…</div>`;
  try {
    if (view.kind === "summary") {
      main.innerHTML = renderSummary();
      main.querySelectorAll("[data-open]").forEach((tr) =>
        tr.onclick = () => show({ kind: "report", key: tr.dataset.open }));
      const toggle = main.querySelector("#toggle-old");
      if (toggle) toggle.onclick = () => { state.showAll = !state.showAll; show(view); };
      return;
    }
    if (view.kind === "report") {
      const data = await api(`/api/report?path=${encodeURIComponent(view.key)}`);
      main.innerHTML = renderReport(data);
      wireRows(null);
      return;
    }
    if (view.kind === "batch") {
      const data = await api(`/api/batch?name=${encodeURIComponent(view.key)}`);
      main.innerHTML = renderBatch(data);
      wireRows(async (id, detail) => {
        if (detail.dataset.loaded) return;
        try {
          const t = await api(`/api/transcript?batch=${encodeURIComponent(view.key)}&case=${encodeURIComponent(id)}`);
          detail.querySelector("td").innerHTML = renderTranscript(t);
          detail.dataset.loaded = "1";
        } catch (err) {
          detail.querySelector("td").innerHTML = `<span style="color:var(--fail)">${esc(err.message)}</span>`;
        }
      });
    }
  } catch (err) {
    main.innerHTML = `<div class="banner bad"><b>Could not load that.</b>${esc(err.message)}</div>`;
  }
}

// ── chrome ───────────────────────────────────────────────────────────────────

function renderDeployChip() {
  const d = state.overview.deploy;
  if (!d) return;
  const slots = d.slots || {};
  const live = slots[d.active] || {};
  $("#deploy-chip").innerHTML =
    `<span class="badge info">${esc(d.active)} live</span>
     <span style="color:var(--text-faint);font-size:12px">
       ${esc(live.variant || d.variant || "?")} · ${esc(live.version || d.version || "?")}</span>`;
}

async function boot() {
  state.overview = await api("/api/overview");
  renderDeployChip();
  await show(state.view);
}

$("#reload").onclick = () => boot();

$("#theme").onclick = () => {
  const el = document.documentElement;
  const light = el.dataset.theme === "light";
  el.dataset.theme = light ? "dark" : "light";
  $("#theme").textContent = light ? "Light" : "Dark";
  try { localStorage.setItem("creuset-theme", el.dataset.theme); } catch (e) { /* private mode */ }
};

$("#check-infra").onclick = async () => {
  const chip = $("#infra-chip");
  chip.innerHTML = `<span style="color:var(--text-faint);font-size:12px">checking…</span>`;
  try {
    const r = await api("/api/infra");
    chip.innerHTML = r.ready
      ? `<span class="badge pass">live runs ready</span>`
      : `<span class="badge warn" title="${esc(r.problems.join(" | "))}">live runs blocked</span>`;
  } catch (err) {
    chip.innerHTML = `<span class="badge fail">check failed</span>`;
  }
};

try {
  const saved = localStorage.getItem("creuset-theme");
  if (saved) {
    document.documentElement.dataset.theme = saved;
    $("#theme").textContent = saved === "light" ? "Dark" : "Light";
  }
} catch (e) { /* private mode */ }

boot().catch((err) => {
  $("#main").innerHTML = `<div class="banner bad"><b>Could not reach the server.</b>${esc(err.message)}</div>`;
});
