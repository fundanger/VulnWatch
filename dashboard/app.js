// CVE Emailer Dashboard — frontend logic
// All data from /api/* endpoints served by api.py

const API = "";  // same origin; change to e.g. "http://localhost:5000" if cross-origin

// ── Navigation ───────────────────────────────────────────────────────────────

const sections = document.querySelectorAll(".section");
const navLinks = document.querySelectorAll(".nav-link");

function showSection(name) {
  sections.forEach(s => s.classList.toggle("active", s.id === `section-${name}`));
  navLinks.forEach(l => l.classList.toggle("active", l.dataset.section === name));
}

navLinks.forEach(l => l.addEventListener("click", e => {
  if (!l.dataset.section) return; // external link (Docs)
  e.preventDefault();
  const sec = l.dataset.section;
  showSection(sec);
  if (sec === "overview")   { loadDashboard(); loadTopCves(); loadTrend(); loadKwPerf(); }
  if (sec === "history")    loadHistory();
  if (sec === "profiles")   loadProfiles();
  if (sec === "browse")     loadBrowseTables();
  if (sec === "digest")     loadDigestQueue();
  if (sec === "settings")   loadSettings();
  if (sec === "watchlist")  loadWatchlist();
}));

// ── Health check ─────────────────────────────────────────────────────────────

async function checkHealth() {
  const dot  = document.getElementById("health-dot");
  const text = document.getElementById("health-text");
  try {
    const r = await fetch(`${API}/health`);
    const j = await r.json();
    if (j.status === "ok") {
      dot.className = "health-dot ok";
      text.textContent = "Connected";
    } else {
      throw new Error(j.error || "DB error");
    }
  } catch (e) {
    dot.className = "health-dot err";
    text.textContent = "API unreachable";
  }
}

setInterval(checkHealth, 30_000);
checkHealth();

// ── Utilities ─────────────────────────────────────────────────────────────────

function sevBadge(sev) {
  const s = (sev || "UNKNOWN").toUpperCase();
  return `<span class="badge badge-${s}">${s}</span>`;
}

function kevBadge(kev) {
  return kev ? `<span class="badge badge-kev">KEV</span>` : "";
}

function epssStr(val) {
  if (val == null) return "—";
  return (val * 100).toFixed(2) + "%";
}

function scoreStr(val) {
  return val != null ? Number(val).toFixed(1) : "—";
}

function truncate(s, n = 100) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n) + "…" : s;
}

// ── Dashboard / Overview ─────────────────────────────────────────────────────

async function loadDashboard() {
  try {
    const r = await fetch(`${API}/api/dashboard`);
    const d = await r.json();

    document.getElementById("stat-total").textContent    = d.total_cves ?? "—";
    document.getElementById("stat-critical").textContent = d.totals?.CRITICAL ?? 0;
    document.getElementById("stat-high").textContent     = d.totals?.HIGH ?? 0;
    document.getElementById("stat-medium").textContent   = d.totals?.MEDIUM ?? 0;
    document.getElementById("stat-low").textContent      = d.totals?.LOW ?? 0;
    document.getElementById("stat-kev").textContent      = d.kev_total ?? "—";

    const tbody = document.getElementById("keyword-tbody");
    tbody.innerHTML = "";
    (d.per_keyword || []).forEach(kw => {
      const total = (kw.CRITICAL||0) + (kw.HIGH||0) + (kw.MEDIUM||0) + (kw.LOW||0) + (kw.NONE||0) + (kw.UNKNOWN||0);
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td>${escHtml(kw.keyword)}</td>
          <td class="num critical-col">${kw.CRITICAL || 0}</td>
          <td class="num high-col">${kw.HIGH || 0}</td>
          <td class="num medium-col">${kw.MEDIUM || 0}</td>
          <td class="num low-col">${kw.LOW || 0}</td>
          <td class="num">${kw.kev || 0}</td>
          <td class="num">${total}</td>
        </tr>
      `);
    });

    const ul = document.getElementById("recent-scans");
    ul.innerHTML = "";
    (d.recent_scans || []).forEach(s => {
      const ts  = (s.started_at || "").slice(0, 16);
      const err = s.error ? `<span class="scan-err"> ERR</span>` : "";
      ul.insertAdjacentHTML("beforeend", `
        <li>
          <span class="scan-time">${escHtml(ts)}</span>
          <span class="scan-new"> +${s.new_cves || 0} new</span>
          <span class="scan-upd"> ~${s.updated_cves || 0} upd</span>
          ${err}
        </li>
      `);
    });
  } catch (e) {
    console.error("loadDashboard:", e);
  }
}

document.getElementById("btn-refresh-dashboard").addEventListener("click", () => { loadDashboard(); loadTopCves(); loadTrend(); });

// ── Browse CVEs ───────────────────────────────────────────────────────────────

let _browseRows = [];
let _browseTable = "";

async function loadBrowseTables() {
  try {
    const r = await fetch(`${API}/api/tables`);
    const tables = await r.json();
    const sel = document.getElementById("br-table");
    sel.innerHTML = `<option value="">Select keyword…</option>`;
    tables.forEach(t => sel.insertAdjacentHTML("beforeend", `<option value="${escHtml(t)}">${escHtml(t)}</option>`));
  } catch (e) {
    console.error("loadBrowseTables:", e);
  }
}

async function doBrowseSearch() {
  const table = document.getElementById("br-table").value;
  if (!table) { alert("Select a keyword table first."); return; }

  const params = new URLSearchParams({
    table,
    search:       document.getElementById("br-search").value,
    min_severity: document.getElementById("br-severity").value,
    date_from:    document.getElementById("br-date-from").value,
    date_to:      document.getElementById("br-date-to").value,
    limit: 500,
  });

  try {
    const r = await fetch(`${API}/api/cves?${params}`);
    _browseRows  = await r.json();
    _browseTable = table;
    await renderBrowseResults();
  } catch (e) {
    console.error("doBrowseSearch:", e);
  }
}

let _reviewedMap = {};  // cve_id -> bool, cached per browse load

async function _loadReviewedMap(rows) {
  // Fetch all reviews once and index them
  try {
    const r = await fetch(`${API}/api/reviews`);
    const all = await r.json();
    _reviewedMap = {};
    all.forEach(rv => { _reviewedMap[rv.cve_id] = !!rv.reviewed; });
  } catch {}
}

async function renderBrowseResults() {
  await _loadReviewedMap(_browseRows);

  const reviewFilter = document.getElementById("br-reviewed").value;
  let rows = _browseRows;
  if (reviewFilter === "reviewed")   rows = rows.filter(r => _reviewedMap[r.cve_id]);
  if (reviewFilter === "unreviewed") rows = rows.filter(r => !_reviewedMap[r.cve_id]);

  const tbody = document.getElementById("browse-tbody");
  tbody.innerHTML = "";
  rows.forEach((row, idx) => {
    const reviewed = _reviewedMap[row.cve_id];
    tbody.insertAdjacentHTML("beforeend", `
      <tr class="clickable${reviewed ? " row-reviewed" : ""}" data-cve="${escHtml(row.cve_id)}" data-idx="${idx}">
        <td><code>${escHtml(row.cve_id)}</code></td>
        <td>${sevBadge(row.severity)}</td>
        <td class="num">${scoreStr(row.cvss_score)}</td>
        <td class="num">${epssStr(row.epss_score)}</td>
        <td>${kevBadge(row.kev)}</td>
        <td>${escHtml(row.keyword || "")}</td>
        <td>${escHtml((row.publish_date || "").slice(0, 10))}</td>
        <td>${reviewed ? `<span class="badge-reviewed">✓</span>` : ""}</td>
        <td>${escHtml(truncate(row.description, 90))}</td>
      </tr>
    `);
  });
  document.getElementById("browse-tbody").querySelectorAll("tr[data-cve]").forEach(tr => {
    tr.addEventListener("click", () => {
      const idx = _browseRows.findIndex(r => r.cve_id === tr.dataset.cve);
      if (idx >= 0) openDetail(_browseRows[idx]);
    });
  });
  document.getElementById("browse-status").textContent = `${rows.length} result(s) — click a row for detail`;
}

document.getElementById("br-reviewed").addEventListener("change", renderBrowseResults);

document.getElementById("btn-browse-search").addEventListener("click", () => doBrowseSearchPaged(0));
document.getElementById("br-search").addEventListener("keydown", e => { if (e.key === "Enter") doBrowseSearchPaged(0); });

document.getElementById("btn-browse-export").addEventListener("click", () => {
  if (!_browseRows.length) { alert("Run a search first."); return; }
  const headers = ["cve_id","severity","cvss_score","epss_score","kev","keyword","publish_date","cwe","description"];
  const csv = [headers.join(","), ..._browseRows.map(r =>
    headers.map(h => `"${String(r[h] ?? "").replace(/"/g,'""')}"`).join(",")
  )].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], {type:"text/csv"}));
  a.download = `cve_export_${_browseTable}_${Date.now()}.csv`;
  a.click();
});

// ── CVE Detail overlay ────────────────────────────────────────────────────────

let _detailRow = null;

async function openDetail(row) {
  _detailRow = row;
  let refs = [];
  try { refs = JSON.parse(row.references_json || "[]"); } catch {}

  const refLinks = refs.length
    ? refs.map(u => `<a href="${escHtml(u)}" target="_blank" rel="noopener">${escHtml(u)}</a>`).join("")
    : "<span class='muted'>None</span>";

  const epss = row.epss_score != null
    ? `${(row.epss_score * 100).toFixed(2)}% (${(row.epss_percentile * 100 || 0).toFixed(0)}th percentile)`
    : "—";

  document.getElementById("detail-content").innerHTML = `
    <h2>${escHtml(row.cve_id)}</h2>
    <dl class="dl">
      <dt>Severity</dt>   <dd>${sevBadge(row.severity)} ${scoreStr(row.cvss_score)} CVSS</dd>
      <dt>EPSS</dt>       <dd>${escHtml(epss)}</dd>
      <dt>CISA KEV</dt>   <dd>${row.kev ? `<span class="badge badge-kev">Actively Exploited</span>` : "No"}</dd>
      <dt>Keyword</dt>    <dd>${escHtml(row.keyword || "")}</dd>
      <dt>Published</dt>  <dd>${escHtml((row.publish_date || "").slice(0, 10))}</dd>
      <dt>Modified</dt>   <dd>${escHtml((row.last_modified || "").slice(0, 10))}</dd>
      <dt>CWE</dt>        <dd>${escHtml(row.cwe || "—")}</dd>
      <dt>CPE</dt>        <dd><small>${escHtml(row.cpe || "—")}</small></dd>
    </dl>
    <div class="desc">${escHtml(row.description || "")}</div>
    <div class="refs"><strong>References</strong><br>${refLinks}</div>
  `;

  // Load review state + notes
  const actionMsg = document.getElementById("detail-action-msg");
  const notesEl   = document.getElementById("detail-notes");
  const btnRev    = document.getElementById("btn-detail-reviewed");
  notesEl.value   = "";
  actionMsg.textContent = "";
  btnRev.textContent    = "✓ Mark Reviewed";
  btnRev.className      = "btn-sm";
  try {
    const rv = await fetch(`${API}/api/review/${encodeURIComponent(row.cve_id)}`);
    const rj = await rv.json();
    if (rj.reviewed) {
      btnRev.textContent = "✓ Reviewed";
      btnRev.className   = "btn-sm btn-reviewed";
    }
    notesEl.value = rj.notes || "";
  } catch {}

  document.getElementById("detail-overlay").classList.remove("hidden");
}

document.getElementById("btn-detail-close").addEventListener("click", () => {
  document.getElementById("detail-overlay").classList.add("hidden");
});
document.getElementById("detail-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) e.currentTarget.classList.add("hidden");
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape") document.getElementById("detail-overlay").classList.add("hidden");
});

document.getElementById("btn-detail-watchlist").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg = document.getElementById("detail-action-msg");
  try {
    const r = await fetch(`${API}/api/watchlist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id: _detailRow.cve_id, keyword: _detailRow.keyword || "" }),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = "Added to watchlist!"; msg.className = "form-msg ok"; }
    else       { msg.textContent = j.error || "Failed";   msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 3000);
});

document.getElementById("btn-detail-reviewed").addEventListener("click", async () => {
  if (!_detailRow) return;
  const btn = document.getElementById("btn-detail-reviewed");
  const msg = document.getElementById("detail-action-msg");
  const alreadyReviewed = btn.classList.contains("btn-reviewed");
  try {
    const r = await fetch(`${API}/api/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id: _detailRow.cve_id, reviewed: !alreadyReviewed, notes: document.getElementById("detail-notes").value }),
    });
    const j = await r.json();
    if (j.ok) {
      if (!alreadyReviewed) { btn.textContent = "✓ Reviewed"; btn.className = "btn-sm btn-reviewed"; }
      else                  { btn.textContent = "✓ Mark Reviewed"; btn.className = "btn-sm"; }
      msg.textContent = alreadyReviewed ? "Marked unreviewed" : "Marked reviewed!";
      msg.className   = "form-msg ok";
    }
  } catch {}
  setTimeout(() => { msg.textContent = ""; }, 2500);
});

document.getElementById("btn-detail-save-notes").addEventListener("click", async () => {
  if (!_detailRow) return;
  const notes = document.getElementById("detail-notes").value;
  const msg   = document.getElementById("detail-action-msg");
  try {
    const r = await fetch(`${API}/api/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id: _detailRow.cve_id, reviewed: document.getElementById("btn-detail-reviewed").classList.contains("btn-reviewed"), notes }),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = "Notes saved!"; msg.className = "form-msg ok"; }
    else       { msg.textContent = j.error || "Failed"; msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  // Also sync to watchlist if present
  try {
    await fetch(`${API}/api/watchlist/${encodeURIComponent(_detailRow.cve_id)}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ notes }),
    });
  } catch {}
  setTimeout(() => { msg.textContent = ""; }, 2500);
});

// ── Scan History ──────────────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const r = await fetch(`${API}/api/history?limit=100`);
    const rows = await r.json();
    const tbody = document.getElementById("history-tbody");
    tbody.innerHTML = "";
    rows.forEach((row, idx) => {
      const hasDetail = row.keywords && row.keywords.trim();
      const chevron   = hasDetail ? "▶" : "";
      const tr = document.createElement("tr");
      tr.className = hasDetail ? "clickable" : "";
      tr.innerHTML = `
        <td class="expand-chevron">${escHtml(chevron)}</td>
        <td>${escHtml((row.started_at || "").slice(0, 16))}</td>
        <td>${escHtml((row.finished_at || "").slice(0, 16))}</td>
        <td>${escHtml(truncate(row.keywords || "", 40))}</td>
        <td class="num">${row.new_cves ?? 0}</td>
        <td class="num">${row.updated_cves ?? 0}</td>
        <td>${row.emailed ? "✓" : ""}</td>
        <td><small style="color:${row.error ? "var(--critical)" : "inherit"}">${escHtml(truncate(row.error || "", 40))}</small></td>
      `;
      tbody.appendChild(tr);

      if (hasDetail) {
        const detailTr = document.createElement("tr");
        detailTr.className = "history-detail-row hidden";
        const kwList = row.keywords.split(",").map(k => k.trim()).filter(Boolean);
        detailTr.innerHTML = `
          <td></td>
          <td colspan="7">
            <div class="history-detail">
              <strong>Keywords scanned:</strong>
              ${kwList.map(k => `<span class="search-chip" style="cursor:default">${escHtml(k)}</span>`).join("")}
              <div style="margin-top:.5rem;color:var(--muted);font-size:12px">
                Duration: ${_duration(row.started_at, row.finished_at)}
                ${row.error ? `<span style="color:var(--critical);margin-left:1rem">Error: ${escHtml(row.error)}</span>` : ""}
              </div>
            </div>
          </td>
        `;
        tbody.appendChild(detailTr);

        tr.addEventListener("click", () => {
          const open = !detailTr.classList.contains("hidden");
          detailTr.classList.toggle("hidden", open);
          tr.querySelector(".expand-chevron").textContent = open ? "▶" : "▼";
        });
      }
    });
  } catch (e) {
    console.error("loadHistory:", e);
  }
}

function _duration(start, end) {
  if (!start || !end) return "—";
  try {
    const s = new Date(start), e = new Date(end);
    const sec = Math.round((e - s) / 1000);
    if (sec < 60) return `${sec}s`;
    return `${Math.floor(sec/60)}m ${sec%60}s`;
  } catch { return "—"; }
}

// ── Watchlist ─────────────────────────────────────────────────────────────────

let _watchlistData = [];

async function loadWatchlist() {
  try {
    const r = await fetch(`${API}/api/watchlist`);
    _watchlistData = await r.json();
    const tbody   = document.getElementById("watchlist-tbody");
    const emptyEl = document.getElementById("watchlist-empty");
    tbody.innerHTML = "";

    if (!_watchlistData.length) {
      emptyEl.style.display = "";
      return;
    }
    emptyEl.style.display = "none";

    _watchlistData.forEach((w, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escHtml(w.cve_id)}</code></td>
        <td>${escHtml(w.keyword || "—")}</td>
        <td>${sevBadge(w.severity || "UNKNOWN")}</td>
        <td class="num">${scoreStr(w.cvss_score)}</td>
        <td class="num">${epssStr(w.epss_score)}</td>
        <td>${kevBadge(w.kev)}</td>
        <td>${escHtml((w.added_at || "").slice(0, 10))}</td>
        <td class="watchlist-notes-cell" data-idx="${idx}">${escHtml(truncate(w.notes || "", 50))}</td>
        <td><button class="btn-sm btn-watchlist-remove" data-cve="${escHtml(w.cve_id)}">Remove</button></td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll(".btn-watchlist-remove").forEach(btn => {
      btn.addEventListener("click", async () => {
        await fetch(`${API}/api/watchlist/${encodeURIComponent(btn.dataset.cve)}`, { method: "DELETE" });
        loadWatchlist();
      });
    });
  } catch (e) { console.error("loadWatchlist:", e); }
}

document.getElementById("btn-watchlist-add").addEventListener("click", async () => {
  const cveId = document.getElementById("watchlist-add-id").value.trim().toUpperCase();
  if (!cveId) return;
  try {
    const r = await fetch(`${API}/api/watchlist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cve_id: cveId }),
    });
    const j = await r.json();
    if (j.ok) {
      document.getElementById("watchlist-add-id").value = "";
      loadWatchlist();
    } else {
      alert(j.error || "Failed to add CVE");
    }
  } catch (e) { console.error(e); }
});

// ── Profiles ──────────────────────────────────────────────────────────────────

async function loadProfiles() {
  try {
    const r = await fetch(`${API}/api/profiles`);
    const rows = await r.json();
    const tbody = document.getElementById("profiles-tbody");
    tbody.innerHTML = "";
    rows.forEach(p => {
      const digest = p.digest_mode
        ? (p.digest_schedule || "daily").charAt(0).toUpperCase() + (p.digest_schedule || "daily").slice(1)
        : "Immediate";
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td>${escHtml(p.name)}</td>
          <td>${escHtml(p.min_severity || "NONE")}</td>
          <td><small>${escHtml(truncate(p.recipients || "", 50))}</small></td>
          <td>${escHtml(digest)}</td>
          <td>${p.webhook_url || p.slack_webhook ? "Yes" : "—"}</td>
        </tr>
      `);
    });
  } catch (e) {
    console.error("loadProfiles:", e);
  }
}

// ── XSS-safe HTML escape ──────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ── Theme toggle ─────────────────────────────────────────────────────────────

const _themeBtn = document.getElementById("btn-theme");
function _applyTheme(light) {
  document.body.classList.toggle("light-theme", light);
  _themeBtn.textContent = light ? "☾" : "☀";
  localStorage.setItem("cve-theme", light ? "light" : "dark");
}
_themeBtn.addEventListener("click", () => _applyTheme(!document.body.classList.contains("light-theme")));
_applyTheme(localStorage.getItem("cve-theme") === "light");

// ── Trend chart ───────────────────────────────────────────────────────────────

let _trendChart = null;
let _epssChart  = null;

async function loadTrend() {
  const limit = document.getElementById("trend-limit").value;
  try {
    const r = await fetch(`${API}/api/history/trend?limit=${limit}`);
    const rows = await r.json();

    const labels  = rows.map(r => (r.started_at || "").slice(5, 16));
    const newData = rows.map(r => r.new_cves     || 0);
    const updData = rows.map(r => r.updated_cves || 0);

    const ctx = document.getElementById("trend-chart").getContext("2d");
    if (_trendChart) _trendChart.destroy();
    _trendChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [
          { label: "New CVEs",     data: newData, backgroundColor: "rgba(124,58,237,.75)", borderRadius: 3 },
          { label: "Upgraded",     data: updData, backgroundColor: "rgba(217,119,6,.65)",  borderRadius: 3 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#94a3b8", font: { size: 11 } } } },
        scales: {
          x: { stacked: true, ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#2d2d4e" } },
          y: { stacked: true, ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#2d2d4e" } },
        },
      },
    });
  } catch (e) { console.error("loadTrend:", e); }
}

async function loadEpssChart() {
  try {
    const tables = await (await fetch(`${API}/api/tables`)).json();
    if (!tables.length) return;
    const r = await fetch(`${API}/api/cves?table=${encodeURIComponent(tables[0])}&limit=1000`);
    const rows = await r.json();
    const scores = rows.map(r => r.epss_score).filter(v => v != null);
    if (!scores.length) return;

    const buckets = Array(10).fill(0);
    scores.forEach(s => { const b = Math.min(9, Math.floor(s * 10)); buckets[b]++; });
    const labels = ["0–10%","10–20%","20–30%","30–40%","40–50%","50–60%","60–70%","70–80%","80–90%","90–100%"];

    const ctx = document.getElementById("epss-chart").getContext("2d");
    if (_epssChart) _epssChart.destroy();
    _epssChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{ label: "CVEs", data: buckets, backgroundColor: "rgba(147,51,234,.7)", borderRadius: 3 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#2d2d4e" } },
          y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#2d2d4e" } },
        },
      },
    });
  } catch (e) { console.error("loadEpssChart:", e); }
}

document.getElementById("trend-limit").addEventListener("change", loadTrend);

// ── Severity doughnut chart ───────────────────────────────────────────────────

let _severityChart = null;

async function loadSeverityChart() {
  try {
    const r = await fetch(`${API}/api/dashboard`);
    const d = await r.json();
    const totals = d.totals || {};
    const labels  = ["Critical", "High", "Medium", "Low", "None/Unknown"];
    const data    = [
      totals.CRITICAL || 0,
      totals.HIGH     || 0,
      totals.MEDIUM   || 0,
      totals.LOW      || 0,
      (totals.NONE || 0) + (totals.UNKNOWN || 0),
    ];
    const colors = ["#dc2626","#ea580c","#d97706","#65a30d","#374151"];

    const ctx = document.getElementById("severity-chart").getContext("2d");
    if (_severityChart) _severityChart.destroy();
    _severityChart = new Chart(ctx, {
      type: "doughnut",
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "65%",
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", font: { size: 10 }, boxWidth: 10, padding: 8 } },
        },
      },
    });
  } catch (e) { console.error("loadSeverityChart:", e); }
}

// ── Top risk CVEs ─────────────────────────────────────────────────────────────

async function loadTopCves() {
  try {
    const r = await fetch(`${API}/api/cves/top?limit=15`);
    const rows = await r.json();
    const tbody = document.getElementById("top-cves-tbody");
    tbody.innerHTML = "";
    rows.forEach((row, idx) => {
      const tr = document.createElement("tr");
      tr.className = "clickable";
      tr.dataset.idx = idx;
      tr.innerHTML = `
        <td><code>${escHtml(row.cve_id)}</code></td>
        <td>${sevBadge(row.severity)}</td>
        <td class="num">${scoreStr(row.cvss_score)}</td>
        <td class="num">${epssStr(row.epss_score)}</td>
        <td>${kevBadge(row.kev)}</td>
        <td>${escHtml(row.keyword || row._table || "")}</td>
        <td>${escHtml((row.publish_date || "").slice(0,10))}</td>
        <td>${escHtml(truncate(row.description, 80))}</td>
      `;
      tr.addEventListener("click", () => openDetail(row));
      tbody.appendChild(tr);
    });
  } catch (e) { console.error("loadTopCves:", e); }
}

document.getElementById("btn-refresh-top").addEventListener("click", loadTopCves);

// ── Keyword performance ───────────────────────────────────────────────────────

async function loadKwPerf() {
  try {
    const r = await fetch(`${API}/api/keywords/perf`);
    const rows = await r.json();
    const tbody = document.getElementById("kw-perf-tbody");
    tbody.innerHTML = "";
    rows.forEach(kw => {
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td>${escHtml(kw.keyword)}</td>
          <td class="num">${kw.total}</td>
          <td class="num">${kw.avg_cvss != null ? kw.avg_cvss.toFixed(1) : "—"}</td>
          <td class="num">${kw.avg_epss != null ? kw.avg_epss.toFixed(2) + "%" : "—"}</td>
          <td class="num">${kw.kev_count || 0}</td>
          <td>${escHtml(kw.last_scan || "—")}</td>
        </tr>
      `);
    });
  } catch (e) { console.error("loadKwPerf:", e); }
}

document.getElementById("btn-refresh-kw-perf").addEventListener("click", loadKwPerf);

// ── Live scan log (SSE) ───────────────────────────────────────────────────────

let _sseSource = null;
const _logEl  = document.getElementById("scan-log");
const _logSts = document.getElementById("scan-log-status");

function _startSseLog() {
  if (_sseSource) return;
  _sseSource = new EventSource(`${API}/api/scan/log`);
  _logSts.textContent = "Live";
  _logSts.className = "scan-status-text running";

  _sseSource.onmessage = e => {
    if (!e.data || e.data === ": ping") return;
    const line = document.createElement("div");
    line.className = "log-line";
    line.textContent = e.data;
    _logEl.appendChild(line);
    _logEl.scrollTop = _logEl.scrollHeight;
    // cap at 300 lines
    while (_logEl.children.length > 300) _logEl.removeChild(_logEl.firstChild);
  };
  _sseSource.onerror = () => {
    _logSts.textContent = "Disconnected";
    _logSts.className = "scan-status-text";
    _sseSource.close();
    _sseSource = null;
    setTimeout(_startSseLog, 5000); // reconnect
  };
}

document.getElementById("btn-clear-log").addEventListener("click", () => { _logEl.innerHTML = ""; });

// Start SSE log automatically
_startSseLog();

// ── Auto-refresh ──────────────────────────────────────────────────────────────

let _autoRefreshTimer = null;

function _resetAutoRefresh() {
  if (_autoRefreshTimer) clearInterval(_autoRefreshTimer);
  _autoRefreshTimer = null;
  const enabled  = document.getElementById("chk-auto-refresh").checked;
  const interval = parseInt(document.getElementById("sel-refresh-interval").value, 10) * 1000;
  if (enabled) {
    _autoRefreshTimer = setInterval(() => {
      loadDashboard();
      loadTopCves();
      loadTrend();
      loadSeverityChart();
      loadKwPerf();
    }, interval);
  }
}

document.getElementById("chk-auto-refresh").addEventListener("change", _resetAutoRefresh);
document.getElementById("sel-refresh-interval").addEventListener("change", _resetAutoRefresh);

// ── Trigger scan ─────────────────────────────────────────────────────────────

const btnScan    = document.getElementById("btn-trigger-scan");
const scanStatus = document.getElementById("scan-status-text");

async function pollScanStatus() {
  try {
    const r = await fetch(`${API}/api/scan/status`);
    const j = await r.json();
    if (j.running) {
      scanStatus.textContent = "Scan running…";
      scanStatus.className = "scan-status-text running";
      btnScan.disabled = true;
    } else {
      scanStatus.textContent = "";
      btnScan.disabled = false;
    }
  } catch { /* ignore */ }
}

document.getElementById("btn-export-all").addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = `${API}/api/cves/export-all`;
  a.download = "";
  a.click();
});

btnScan.addEventListener("click", async () => {
  btnScan.disabled = true;
  scanStatus.textContent = "Queuing scan…";
  scanStatus.className = "scan-status-text running";
  try {
    const r = await fetch(`${API}/api/scan`, { method: "POST" });
    const j = await r.json();
    if (r.status === 409) {
      scanStatus.textContent = "Already running";
    } else if (j.ok) {
      scanStatus.textContent = "Scan queued";
      setTimeout(pollScanStatus, 1500);
    } else {
      scanStatus.textContent = j.message || "Error";
      btnScan.disabled = false;
    }
  } catch (e) {
    scanStatus.textContent = "Request failed";
    btnScan.disabled = false;
  }
});

setInterval(pollScanStatus, 5000);

// ── Settings ──────────────────────────────────────────────────────────────────

const FIELD_META = {
  "DEFAULT__apiKey":         { label: "NVD API Key",           placeholder: "optional — avoids rate limits" },
  "DEFAULT__checkFrequency": { label: "Check interval (sec)",  placeholder: "3600" },
  "DEFAULT__minSeverity":    { label: "Global min severity",   placeholder: "NONE / LOW / MEDIUM / HIGH / CRITICAL" },
  "DEFAULT__webhookUrl":     { label: "Webhook URL",           placeholder: "https://..." },
  "DEFAULT__slackWebhook":   { label: "Slack webhook URL",     placeholder: "https://hooks.slack.com/..." },
  "EMAIL__senderEmail":      { label: "Sender Gmail",          placeholder: "you@gmail.com" },
  "EMAIL__senderPassword":   { label: "Gmail App Password",    placeholder: "xxxx xxxx xxxx xxxx", password: true },
  "EMAIL__recipientEmail":   { label: "Recipient email(s)",    placeholder: "a@x.com, b@x.com" },
  "EMAIL__subjectLine":      { label: "Email subject",         placeholder: "CVE Alert" },
  "JIRA__url":               { label: "Jira base URL",         placeholder: "https://myorg.atlassian.net" },
  "JIRA__user":              { label: "Jira account email",    placeholder: "me@myorg.com" },
  "JIRA__token":             { label: "Jira API token",        placeholder: "", password: true },
  "JIRA__project_key":       { label: "Jira project key",      placeholder: "SEC" },
  "JIRA__issue_type":        { label: "Jira issue type",       placeholder: "Bug" },
  "SERVICENOW__instance":    { label: "ServiceNow instance",   placeholder: "myorg.service-now.com" },
  "SERVICENOW__user":        { label: "ServiceNow username",   placeholder: "" },
  "SERVICENOW__password":    { label: "ServiceNow password",   placeholder: "", password: true },
  "SERVICENOW__category":    { label: "Incident category",     placeholder: "Security" },
};

let _settingsData = {};

function buildSettingsField(id, field) {
  const meta = FIELD_META[id] || { label: id, placeholder: "" };
  const container = document.getElementById(`fg-${id}`);
  if (!container) return;

  const locked = field.locked;
  const labelEl = document.createElement("label");
  labelEl.className = "form-label";
  labelEl.textContent = meta.label;
  if (locked) {
    const badge = document.createElement("span");
    badge.className = "locked-badge";
    badge.textContent = "ENV";
    labelEl.appendChild(document.createTextNode(" "));
    labelEl.appendChild(badge);
  }

  const input = document.createElement("input");
  input.className = "input-sm";
  input.id = `cfg-${id}`;
  input.type = (meta.password && !locked) ? "password" : "text";
  input.placeholder = meta.placeholder;
  input.value = field.value || "";
  input.disabled = locked;
  if (locked) input.title = "Set via environment variable — edit your .env file to change this.";

  container.appendChild(labelEl);
  container.appendChild(input);
}

async function loadSettings() {
  try {
    const r = await fetch(`${API}/api/config`);
    _settingsData = await r.json();
    for (const [id, field] of Object.entries(_settingsData)) {
      if (id === "DEFAULT__keywords") {
        const ta = document.getElementById("cfg-DEFAULT__keywords");
        if (ta) ta.value = field.value || "";
        continue;
      }
      buildSettingsField(id, field);
    }
  } catch (e) {
    console.error("loadSettings:", e);
  }
}

document.getElementById("settings-form").addEventListener("submit", async e => {
  e.preventDefault();
  const msg = document.getElementById("settings-msg");
  msg.textContent = "Saving…";
  msg.className = "form-msg";

  const payload = {};
  for (const id of Object.keys(_settingsData)) {
    const el = document.getElementById(`cfg-${id}`);
    if (!el || el.disabled) continue;
    payload[id] = el.value;
  }

  try {
    const r = await fetch(`${API}/api/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = "Saved!";
      msg.className = "form-msg ok";
    } else {
      msg.textContent = j.error || "Save failed";
      msg.className = "form-msg err";
    }
  } catch (err) {
    msg.textContent = "Request failed";
    msg.className = "form-msg err";
  }
  setTimeout(() => { msg.textContent = ""; }, 3000);
});

// ── Profiles (full CRUD) ──────────────────────────────────────────────────────

let _editingProfile = null; // null = new, string = existing name

function _openProfileEditor(profile = null) {
  _editingProfile = profile ? profile.name : null;
  document.getElementById("profile-editor-title").textContent = profile ? `Edit — ${escHtml(profile.name)}` : "New Profile";
  document.getElementById("pf-name").value       = profile?.name       || "";
  document.getElementById("pf-name").disabled    = !!profile; // name is the PK — can't rename
  document.getElementById("pf-keywords").value   = profile?.keywords   || "";
  document.getElementById("pf-severity").value   = profile?.min_severity || "MEDIUM";
  document.getElementById("pf-recipients").value = profile?.recipients  || "";
  document.getElementById("pf-webhook").value    = profile?.webhook_url || "";
  document.getElementById("pf-slack").value      = profile?.slack_webhook || "";
  const digest = profile?.digest_mode
    ? (profile.digest_schedule || "daily")
    : "off";
  document.getElementById("pf-digest").value = digest;
  document.getElementById("btn-profile-delete").style.display = profile ? "" : "none";
  document.getElementById("profile-msg").textContent = "";
  document.getElementById("profile-editor").classList.add("visible");
}

function _closeProfileEditor() {
  _editingProfile = null;
  document.getElementById("profile-editor").classList.remove("visible");
}

document.getElementById("btn-profile-new").addEventListener("click", () => _openProfileEditor());
document.getElementById("btn-profile-cancel").addEventListener("click", _closeProfileEditor);

document.getElementById("btn-profile-save").addEventListener("click", async () => {
  const msg = document.getElementById("profile-msg");
  const name = document.getElementById("pf-name").value.trim();
  if (!name) { msg.textContent = "Name is required."; msg.className = "form-msg err"; return; }

  const digestVal = document.getElementById("pf-digest").value;
  const body = {
    name,
    keywords:        document.getElementById("pf-keywords").value.trim(),
    min_severity:    document.getElementById("pf-severity").value,
    recipients:      document.getElementById("pf-recipients").value.trim(),
    webhook_url:     document.getElementById("pf-webhook").value.trim(),
    slack_webhook:   document.getElementById("pf-slack").value.trim(),
    digest_mode:     digestVal !== "off" ? 1 : 0,
    digest_schedule: digestVal !== "off" ? digestVal : "daily",
  };

  try {
    const r = await fetch(`${API}/api/profiles`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = "Saved!"; msg.className = "form-msg ok";
      loadProfiles();
      setTimeout(_closeProfileEditor, 800);
    } else {
      msg.textContent = j.error || "Save failed"; msg.className = "form-msg err";
    }
  } catch (err) {
    msg.textContent = "Request failed"; msg.className = "form-msg err";
  }
});

document.getElementById("btn-profile-delete").addEventListener("click", async () => {
  if (!_editingProfile) return;
  if (!confirm(`Delete profile "${_editingProfile}"?`)) return;
  const msg = document.getElementById("profile-msg");
  try {
    const r = await fetch(`${API}/api/profiles/${encodeURIComponent(_editingProfile)}`, { method: "DELETE" });
    const j = await r.json();
    if (j.ok) {
      loadProfiles();
      _closeProfileEditor();
    } else {
      msg.textContent = j.error || "Delete failed"; msg.className = "form-msg err";
    }
  } catch (err) {
    msg.textContent = "Request failed"; msg.className = "form-msg err";
  }
});

async function loadProfiles() {
  try {
    const r = await fetch(`${API}/api/profiles`);
    const rows = await r.json();
    const tbody = document.getElementById("profiles-tbody");
    tbody.innerHTML = "";
    rows.forEach(p => {
      const digest = p.digest_mode
        ? (p.digest_schedule || "daily").charAt(0).toUpperCase() + (p.digest_schedule || "daily").slice(1)
        : "Immediate";
      const tr = document.createElement("tr");
      tr.className = "clickable";
      tr.innerHTML = `
        <td>${escHtml(p.name)}</td>
        <td>${escHtml(p.min_severity || "NONE")}</td>
        <td><small>${escHtml(truncate(p.recipients || "", 40))}</small></td>
        <td>${escHtml(digest)}</td>
        <td>${p.webhook_url || p.slack_webhook ? "Yes" : "—"}</td>
        <td><button class="btn-sm">Edit</button></td>
      `;
      tr.querySelector("button").addEventListener("click", e => { e.stopPropagation(); _openProfileEditor(p); });
      tr.addEventListener("click", () => _openProfileEditor(p));
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error("loadProfiles:", e);
  }
}

// ── Digest queue ─────────────────────────────────────────────────────────────

async function loadDigestQueue() {
  try {
    const r = await fetch(`${API}/api/digest`);
    const rows = await r.json();
    const container = document.getElementById("digest-groups");
    container.innerHTML = "";

    if (!rows.length) {
      container.innerHTML = '<p class="muted">No CVEs pending in any digest queue.</p>';
      return;
    }

    // Group by profile_name
    const groups = {};
    rows.forEach(r => {
      const p = r.profile_name || "(default)";
      if (!groups[p]) groups[p] = [];
      groups[p].push(r);
    });

    for (const [profile, cves] of Object.entries(groups)) {
      const div = document.createElement("div");
      div.className = "panel";
      div.style.marginBottom = "1.5rem";
      div.innerHTML = `
        <div class="panel-header">
          <h2>${escHtml(profile)} <span class="form-hint">${cves.length} pending</span></h2>
          <button class="btn-sm btn-send-digest" data-profile="${escHtml(profile)}">Send now</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>CVE ID</th><th>Severity</th><th class="num">CVSS</th>
              <th>Keyword</th><th>Queued At</th><th>Description</th>
            </tr></thead>
            <tbody>${cves.map(c => `
              <tr>
                <td><code>${escHtml(c.cve_id)}</code></td>
                <td>${sevBadge(c.severity)}</td>
                <td class="num">${scoreStr(c.cvss_score)}</td>
                <td>${escHtml(c.keyword || "")}</td>
                <td>${escHtml((c.queued_at || "").slice(0,16))}</td>
                <td>${escHtml(truncate(c.description || "", 80))}</td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>
      `;
      container.appendChild(div);
    }

    container.querySelectorAll(".btn-send-digest").forEach(btn => {
      btn.addEventListener("click", async () => {
        const profile = btn.dataset.profile === "(default)" ? "" : btn.dataset.profile;
        btn.disabled = true;
        try {
          const r = await fetch(`${API}/api/digest/send`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ profile_name: profile }),
          });
          const j = await r.json();
          if (j.ok) loadDigestQueue();
        } catch (e) { btn.disabled = false; }
      });
    });
  } catch (e) { console.error("loadDigestQueue:", e); }
}

// ── Notification tests ────────────────────────────────────────────────────────

async function _testNotify(channel) {
  const msg = document.getElementById("test-notify-msg");
  msg.textContent = `Sending ${channel} test…`;
  msg.className = "form-msg";
  try {
    const r = await fetch(`${API}/api/notify/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channel }),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = `${channel} test sent!`; msg.className = "form-msg ok"; }
    else       { msg.textContent = j.error || "Failed";     msg.className = "form-msg err"; }
  } catch (e) { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 4000);
}

document.getElementById("btn-test-email").addEventListener("click",   () => _testNotify("email"));
document.getElementById("btn-test-slack").addEventListener("click",   () => _testNotify("slack"));
document.getElementById("btn-test-webhook").addEventListener("click", () => _testNotify("webhook"));

// ── Saved searches ────────────────────────────────────────────────────────────

function _loadSavedSearches() {
  try { return JSON.parse(localStorage.getItem("cve-saved-searches") || "[]"); } catch { return []; }
}

function _persistSavedSearches(arr) {
  localStorage.setItem("cve-saved-searches", JSON.stringify(arr));
}

function renderSavedSearches() {
  const list = document.getElementById("saved-searches-list");
  const searches = _loadSavedSearches();
  list.innerHTML = "";
  if (!searches.length) {
    list.innerHTML = '<span class="muted">No saved searches yet.</span>';
    return;
  }
  searches.forEach((s, idx) => {
    const chip = document.createElement("span");
    chip.className = "search-chip";
    chip.innerHTML = `${escHtml(s.name)} <button class="chip-del" data-idx="${idx}">✕</button>`;
    chip.querySelector("button").addEventListener("click", e => {
      e.stopPropagation();
      const arr = _loadSavedSearches();
      arr.splice(idx, 1);
      _persistSavedSearches(arr);
      renderSavedSearches();
    });
    chip.addEventListener("click", e => {
      if (e.target.tagName === "BUTTON") return;
      // Navigate to browse and apply filters
      showSection("browse");
      loadBrowseTables().then(() => {
        document.getElementById("br-table").value    = s.table    || "";
        document.getElementById("br-search").value   = s.search   || "";
        document.getElementById("br-severity").value = s.severity || "NONE";
        document.getElementById("br-date-from").value = s.dateFrom || "";
        document.getElementById("br-date-to").value   = s.dateTo   || "";
      });
    });
    list.appendChild(chip);
  });
}

document.getElementById("btn-save-search").addEventListener("click", () => {
  const name = document.getElementById("saved-search-name").value.trim();
  if (!name) return;
  const arr = _loadSavedSearches();
  arr.push({
    name,
    table:    document.getElementById("br-table").value,
    search:   document.getElementById("br-search").value,
    severity: document.getElementById("br-severity").value,
    dateFrom: document.getElementById("br-date-from").value,
    dateTo:   document.getElementById("br-date-to").value,
  });
  _persistSavedSearches(arr);
  document.getElementById("saved-search-name").value = "";
  renderSavedSearches();
});

// ── Browse pagination ─────────────────────────────────────────────────────────

const PAGE_SIZE_BROWSE = 100;
let _browsePage = 0;
let _browseTotalRows = 0;

async function doBrowseSearchPaged(page = 0) {
  const table = document.getElementById("br-table").value;
  if (!table) { alert("Select a keyword table first."); return; }

  _browsePage = page;
  const params = new URLSearchParams({
    table,
    search:       document.getElementById("br-search").value,
    min_severity: document.getElementById("br-severity").value,
    date_from:    document.getElementById("br-date-from").value,
    date_to:      document.getElementById("br-date-to").value,
    limit:  PAGE_SIZE_BROWSE,
    offset: page * PAGE_SIZE_BROWSE,
  });

  try {
    const r = await fetch(`${API}/api/cves?${params}`);
    _browseRows  = await r.json();
    _browseTable = table;
    // Fetch total count (one extra row to detect more pages)
    const countParams = new URLSearchParams({...Object.fromEntries(params), limit: 1, offset: (page + 1) * PAGE_SIZE_BROWSE});
    const rNext = await fetch(`${API}/api/cves?${countParams}`);
    const nextRows = await rNext.json();
    const hasMore = nextRows.length > 0;

    await renderBrowseResults();
    renderPagination(page, hasMore);
  } catch (e) {
    console.error("doBrowseSearchPaged:", e);
  }
}

function renderPagination(page, hasMore) {
  const el = document.getElementById("browse-pagination");
  el.innerHTML = "";
  if (page === 0 && !hasMore) return;

  if (page > 0) {
    const prev = document.createElement("button");
    prev.className = "btn-sm";
    prev.textContent = "← Prev";
    prev.addEventListener("click", () => doBrowseSearchPaged(page - 1));
    el.appendChild(prev);
  }
  const info = document.createElement("span");
  info.className = "page-info";
  info.textContent = `Page ${page + 1}`;
  el.appendChild(info);
  if (hasMore) {
    const next = document.createElement("button");
    next.className = "btn-sm";
    next.textContent = "Next →";
    next.addEventListener("click", () => doBrowseSearchPaged(page + 1));
    el.appendChild(next);
  }
}

// ── Initial load ──────────────────────────────────────────────────────────────

loadDashboard();
loadTopCves();
loadTrend();
loadEpssChart();
loadSeverityChart();
loadKwPerf();
renderSavedSearches();
