// CVE Emailer Dashboard — frontend logic
// All data from /api/* endpoints served by api.py

const API = "";  // same origin; change to e.g. "http://localhost:5000" if cross-origin

// ── Navigation ───────────────────────────────────────────────────────────────

const sections = document.querySelectorAll(".section");
const navLinks = document.querySelectorAll(".nav-link");
const sidebarLinks = document.querySelectorAll(".sidebar-link");

function _sectionLoader(sec) {
  if (sec === "overview")   { loadDashboard(); loadTopCves(); loadTrend(); loadKwPerf(); loadScheduleInfo(); loadScanHealth(); loadMttr(); }
  if (sec === "history")    loadHistory();
  if (sec === "profiles")   loadProfiles();
  if (sec === "browse")     loadBrowseTables();
  if (sec === "digest")     loadDigestQueue();
  if (sec === "settings")   { loadSettings(); loadSavedViews(); renderSavedSearches(); }
  if (sec === "watchlist")  loadWatchlist();
  if (sec === "analytics")  loadAnalytics();
  if (sec === "notifylog")  loadNotifyLog();
  if (sec === "triage")     loadTriage();
  if (sec === "assets")     loadAssets();
  if (sec === "users")      loadUsers();
  if (sec === "threat")     loadThreatSection();
  if (sec === "routing")    loadRoutingRules();
  if (sec === "audit")      loadAuditLog();
}

function showSection(name) {
  sections.forEach(s => {
    const isTarget = s.id === `section-${name}`;
    if (isTarget && !s.classList.contains("active")) {
      // Re-trigger entrance animation by cycling the class
      s.classList.remove("active");
      void s.offsetWidth; // force reflow
      s.classList.add("active");
    } else {
      s.classList.toggle("active", isTarget);
    }
  });
  navLinks.forEach(l => l.classList.toggle("active", l.dataset.section === name));
  sidebarLinks.forEach(l => l.classList.toggle("active", l.dataset.section === name));
}

navLinks.forEach(l => l.addEventListener("click", e => {
  if (!l.dataset.section) return;
  e.preventDefault();
  const sec = l.dataset.section;
  showSection(sec);
  _sectionLoader(sec);
  localStorage.setItem("cve-last-section", sec);
}));

sidebarLinks.forEach(l => l.addEventListener("click", e => {
  if (!l.dataset.section) return;
  e.preventDefault();
  const sec = l.dataset.section;
  showSection(sec);
  _sectionLoader(sec);
  localStorage.setItem("cve-last-section", sec);
}));

// Restore last section on load
(function () {
  const last = localStorage.getItem("cve-last-section");
  if (last && last !== "overview") {
    showSection(last);
    _sectionLoader(last);
  }
})();

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

function _setStatVal(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value;
  el.classList.remove("stat-pop");
  void el.offsetWidth; // force reflow to restart animation
  el.classList.add("stat-pop");
}

function _animateRows(tbodyEl) {
  if (!tbodyEl) return;
  tbodyEl.classList.remove("row-animate");
  void tbodyEl.offsetWidth;
  tbodyEl.classList.add("row-animate");
}

// ── CSRF token helper ─────────────────────────────────────────────────────────
// Reads the csrf_token cookie set by the server and returns fetch options
// that include it in the X-CSRF-Token header for all state-changing requests.
function _csrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

function _postOpts(body, extraHeaders = {}) {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken(), ...extraHeaders },
    body: JSON.stringify(body),
  };
}

function _deleteOpts(extraHeaders = {}) {
  return {
    method: "DELETE",
    headers: { "X-CSRF-Token": _csrfToken(), ...extraHeaders },
  };
}

function _patchOpts(body, extraHeaders = {}) {
  return {
    method: "PATCH",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken(), ...extraHeaders },
    body: JSON.stringify(body),
  };
}

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

    _setStatVal("stat-total",      d.total_cves    ?? "—");
    _setStatVal("stat-critical",   d.totals?.CRITICAL ?? 0);
    _setStatVal("stat-high",       d.totals?.HIGH     ?? 0);
    _setStatVal("stat-medium",     d.totals?.MEDIUM   ?? 0);
    _setStatVal("stat-low",        d.totals?.LOW      ?? 0);
    _setStatVal("stat-kev",        d.kev_total        ?? "—");
    _setStatVal("stat-keywords",   d.total_keywords   ?? "—");
    _setStatVal("stat-assets",     d.asset_count      ?? "—");
    _setStatVal("stat-open-triage", d.open_triage     ?? "—");
    const overdueSub = document.getElementById("stat-overdue-sub");
    if (overdueSub) overdueSub.textContent = d.overdue_count > 0 ? `${d.overdue_count} overdue` : "";

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
    _animateRows(tbody);

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
document.getElementById("stat-card-overdue").addEventListener("click", () => { showSection("triage"); _sectionLoader("triage"); });

// ── Browse CVEs ───────────────────────────────────────────────────────────────

let _browseRows = [];
let _browseTable = "";

async function loadBrowseTables(autoSearch = true) {
  try {
    const r = await fetch(`${API}/api/tables`);
    const tables = await r.json();
    const sel = document.getElementById("br-table");
    sel.innerHTML = `<option value="">All keywords…</option>`;
    tables.forEach(t => sel.insertAdjacentHTML("beforeend", `<option value="${escHtml(t)}">${escHtml(t)}</option>`));
    if (autoSearch && !_browseRows.length) doBrowseSearchPaged(0);
  } catch (e) {
    console.error("loadBrowseTables:", e);
  }
}

async function doBrowseSearch() {
  const table = document.getElementById("br-table").value;

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
let _triageMap   = {};  // cve_id -> {status, assignee, due_date}

async function _loadReviewedMap(rows) {
  try {
    const r = await fetch(`${API}/api/reviews`);
    const all = await r.json();
    _reviewedMap = {};
    all.forEach(rv => { _reviewedMap[rv.cve_id] = !!rv.reviewed; });
  } catch {}
}

async function _loadTriageMap() {
  try {
    const r = await fetch(`${API}/api/triage`);
    const all = await r.json();
    _triageMap = {};
    all.forEach(t => { _triageMap[t.cve_id] = t; });
  } catch {}
}

// renderBrowseResults is defined below (after bulk/QF logic) as _origRenderBrowse,
// but declared here so earlier code can reference it before the definition.
async function renderBrowseResults() { await _origRenderBrowse(); }

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
// Track suppressed CVE IDs in memory so we don't re-prompt per session
const _suppressedIds = new Set();

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

  // Set sticky panel header title
  const titleEl = document.getElementById("detail-panel-title");
  if (titleEl) titleEl.textContent = row.cve_id;

  // Severity upgrade diff — show if current differs from last-alerted values
  const alertedSev   = row.alerted_severity || "";
  const alertedScore = row.alerted_score    != null ? row.alerted_score : null;
  const sevUpgraded  = alertedSev && alertedSev !== (row.severity || "").toUpperCase() &&
                       alertedSev !== (row.severity || "");
  const scoreUpgraded = alertedScore != null && row.cvss_score != null &&
                        (row.cvss_score - alertedScore) >= 1.0;
  const upgradeBanner = (sevUpgraded || scoreUpgraded)
    ? `<div class="upgrade-banner">
        <span class="upgrade-icon">⬆</span>
        <strong>Severity upgraded</strong>
        ${sevUpgraded   ? `<span class="upgrade-from">${escHtml(alertedSev)}</span> → ${sevBadge(row.severity)}` : ""}
        ${scoreUpgraded ? `<span class="upgrade-score-diff">CVSS ${escHtml(String(alertedScore))} → ${escHtml(scoreStr(row.cvss_score))}</span>` : ""}
      </div>`
    : "";

  document.getElementById("detail-content").innerHTML = `
    ${upgradeBanner}
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

  // Load triage state
  try {
    const tr = await fetch(`${API}/api/triage/${encodeURIComponent(row.cve_id)}`);
    const tj = await tr.json();
    document.getElementById("detail-triage-status").value   = tj.status   || "open";
    document.getElementById("detail-triage-assignee").value = tj.assignee || "";
    document.getElementById("detail-triage-due").value      = tj.due_date || "";
  } catch {
    document.getElementById("detail-triage-status").value   = "open";
    document.getElementById("detail-triage-assignee").value = "";
    document.getElementById("detail-triage-due").value      = "";
  }

  // Load CVSS vector breakdown if available
  _loadCvssVector(row);

  document.getElementById("detail-overlay").classList.remove("hidden");

  // Wire collapsible headers — inject chevron once, then toggle on click
  document.querySelectorAll(".detail-block").forEach(block => {
    const hdr = block.querySelector(".detail-block-header");
    if (!hdr || hdr.dataset.colWired) return;
    hdr.dataset.colWired = "1";
    if (!hdr.querySelector(".detail-block-chevron")) {
      hdr.insertAdjacentHTML("beforeend", `<span class="detail-block-chevron">▼</span>`);
    }
    hdr.addEventListener("click", e => {
      // Don't collapse when clicking buttons inside the header
      if (e.target.closest("button")) return;
      block.classList.toggle("collapsed");
    });
  });
}

function closeDetailOverlay() {
  const ov = document.getElementById("detail-overlay");
  if (ov.classList.contains("hidden")) return;
  ov.classList.add("closing");
  setTimeout(() => { ov.classList.add("hidden"); ov.classList.remove("closing"); }, 170);
}

document.getElementById("btn-detail-close").addEventListener("click", closeDetailOverlay);
document.getElementById("detail-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeDetailOverlay();
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape") closeDetailOverlay();
});

document.getElementById("btn-detail-watchlist").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg = document.getElementById("detail-action-msg");
  try {
    const r = await fetch(`${API}/api/watchlist`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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
    _animateRows(tbody);
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
        await fetch(`${API}/api/watchlist/${encodeURIComponent(btn.dataset.cve)}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
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
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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
    _animateRows(tbody);
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
    _animateRows(tbody);
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
    const r = await fetch(`${API}/api/scan`, { method: "POST", headers: { "X-CSRF-Token": _csrfToken() } });
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
  "DEFAULT__apiKey":         { label: "NVD API Key",           placeholder: "optional — avoids rate limits", password: true },
  "DEFAULT__checkFrequency": { label: "Check interval (sec)",  placeholder: "3600" },
  "DEFAULT__minSeverity":    { label: "Global min severity",   placeholder: "NONE / LOW / MEDIUM / HIGH / CRITICAL" },
  "DEFAULT__webhookUrl":     { label: "Webhook URL",           placeholder: "https://...", password: true },
  "DEFAULT__slackWebhook":   { label: "Slack webhook URL",     placeholder: "https://hooks.slack.com/...", password: true },
  "EMAIL__senderEmail":      { label: "Sender Gmail",          placeholder: "you@gmail.com" },
  "EMAIL__senderPassword":   { label: "Gmail App Password",    placeholder: "xxxx xxxx xxxx xxxx", password: true },
  "EMAIL__recipientEmail":   { label: "Recipient email(s)",    placeholder: "a@x.com, b@x.com" },
  "EMAIL__subjectLine":      { label: "Email subject",         placeholder: "CVE Alert" },
  "JIRA__url":               { label: "Jira base URL",         placeholder: "https://myorg.atlassian.net" },
  "JIRA__user":              { label: "Jira account email",    placeholder: "me@myorg.com" },
  "JIRA__token":             { label: "Jira API token",        placeholder: "", password: true },
  "JIRA__project_key":       { label: "Jira project key",      placeholder: "SEC" },
  "JIRA__issue_type":        { label: "Jira issue type",       placeholder: "Bug" },
  "SERVICENOW__instance":    { label: "ServiceNow instance",      placeholder: "myorg.service-now.com" },
  "SERVICENOW__user":        { label: "ServiceNow username",      placeholder: "" },
  "SERVICENOW__password":    { label: "ServiceNow password",      placeholder: "", password: true },
  "SERVICENOW__category":    { label: "Incident category",        placeholder: "Security" },
  "DEFAULT__teamsWebhook":      { label: "Teams incoming webhook URL",       placeholder: "https://outlook.office.com/webhook/…" },
  "DEFAULT__pagerdutyKey":      { label: "PagerDuty routing key",            placeholder: "", password: true },
  "DEFAULT__opsgenieKey":       { label: "Opsgenie API key",                 placeholder: "", password: true },
  "REPORT__reportSchedule":     { label: "Report schedule",                  placeholder: "off / daily / weekly" },
  "REPORT__reportRecipients":   { label: "Report recipient email(s)",        placeholder: "ciso@org.com, team@org.com" },
};

let _settingsData = {};

// Sentinel displayed in password fields after a value has been saved.
// Fields showing this value are skipped when building the save payload.
const _MASK_DISPLAY = "••••••••••••••••";

function _applyMask(input) {
  input.type = "text";
  input.value = _MASK_DISPLAY;
  input.dataset.masked = "1";
}

function _clearMask(input) {
  input.type = "password";
  input.value = "";
  delete input.dataset.masked;
}

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
  input.placeholder = meta.placeholder;
  input.disabled = locked;
  if (locked) input.title = "Set via environment variable — edit your .env file to change this.";

  if (meta.password && !locked) {
    if (field.value) {
      // Value already exists — show mask immediately
      input.type = "text";
      input.value = _MASK_DISPLAY;
      input.dataset.masked = "1";
    } else {
      input.type = "password";
    }
    input.addEventListener("focus", () => {
      if (input.dataset.masked) _clearMask(input);
    });
    input.addEventListener("blur", () => {
      // If user cleared the field without typing anything new, restore mask
      if (!input.value && field.value) _applyMask(input);
    });
  } else {
    input.type = "text";
    input.value = field.value || "";
  }

  container.innerHTML = "";
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
    // Skip fields still showing the obfuscation mask — value hasn't changed
    if (el.dataset.masked) continue;
    payload[id] = el.value;
  }

  try {
    const r = await fetch(`${API}/api/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify(payload),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = "Saved!";
      msg.className = "form-msg ok";
      // Update in-memory cache and re-mask any sensitive fields that now have values
      for (const [id, val] of Object.entries(payload)) {
        if (_settingsData[id]) _settingsData[id].value = val;
        const meta = FIELD_META[id];
        if (meta && meta.password && val) {
          const el = document.getElementById(`cfg-${id}`);
          if (el) _applyMask(el);
        }
      }
      // Re-apply report schedule if it changed
      if (payload["REPORT__reportSchedule"] !== undefined) {
        fetch(`${API}/api/report/schedule`, { method: "POST", headers: { "X-CSRF-Token": _csrfToken() } }).catch(() => {});
      }
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
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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
    const r = await fetch(`${API}/api/profiles/${encodeURIComponent(_editingProfile)}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
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
    // Schedule preview
    const previewData = await (await fetch(`${API}/api/digest/preview`)).json();
    const previewPanel = document.getElementById("digest-preview-panel");
    const previewTbody = document.getElementById("digest-preview-tbody");
    if (previewData.length) {
      previewPanel.style.display = "";
      previewTbody.innerHTML = "";
      previewData.forEach(p => {
        const fmt = s => s ? new Date(s).toLocaleString() : "—";
        const nextLabel = p.next_fire ? fmt(p.next_fire) : (p.last_sent ? "—" : "Next scan");
        previewTbody.insertAdjacentHTML("beforeend", `
          <tr>
            <td><strong>${escHtml(p.profile)}</strong></td>
            <td>${escHtml(p.schedule)}</td>
            <td class="num">${p.pending}</td>
            <td><small class="muted">${fmt(p.last_sent)}</small></td>
            <td><small>${escHtml(nextLabel)}</small></td>
          </tr>
        `);
      });
    } else {
      previewPanel.style.display = "none";
    }

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
            headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
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

document.getElementById("btn-quick-test-notify").addEventListener("click", async () => {
  const btn = document.getElementById("btn-quick-test-notify");
  const msg = document.getElementById("quick-test-notify-msg");
  btn.disabled = true;
  msg.textContent = "Sending…"; msg.className = "form-msg";
  // Try each configured channel; first one that responds ok wins
  for (const ch of ["email", "slack", "webhook"]) {
    try {
      const r = await fetch(`${API}/api/notify/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
        body: JSON.stringify({ channel: ch }),
      });
      const j = await r.json();
      if (j.ok) {
        msg.textContent = `Test sent via ${ch}`; msg.className = "form-msg ok";
        btn.disabled = false;
        setTimeout(() => { msg.textContent = ""; }, 4000);
        return;
      }
    } catch {}
  }
  msg.textContent = "No channels configured"; msg.className = "form-msg err";
  btn.disabled = false;
  setTimeout(() => { msg.textContent = ""; }, 4000);
});

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
      loadBrowseTables(false).then(() => {
        document.getElementById("br-table").value    = s.table    || "";
        document.getElementById("br-search").value   = s.search   || "";
        document.getElementById("br-severity").value = s.severity || "NONE";
        document.getElementById("br-date-from").value = s.dateFrom || "";
        document.getElementById("br-date-to").value   = s.dateTo   || "";
        doBrowseSearchPaged(0);
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
  const tableEl = document.getElementById("br-table");
  if (!tableEl.value && tableEl.options.length <= 1) {
    document.getElementById("browse-status").textContent = "No keyword tables found — run a scan first.";
    return;
  }

  _browsePage = page;
  const params = new URLSearchParams({
    table: tableEl.value,
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
    _browseTable = tableEl.value;
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

// ── Schedule countdown ────────────────────────────────────────────────────────

let _schedInfo = null;
let _schedCountdownTimer = null;

async function loadScheduleInfo() {
  try {
    const [si, cfg] = await Promise.all([
      fetch(`${API}/api/schedule/info`).then(r => r.json()),
      fetch(`${API}/api/config`).then(r => r.json()),
    ]);
    _schedInfo = si;
    document.getElementById("sched-last").textContent     = (si.last_scan || "—").slice(0, 16);
    const freq = si.check_frequency || 3600;
    const h = Math.floor(freq / 3600), m = Math.floor((freq % 3600) / 60);
    document.getElementById("sched-interval").textContent = h ? `${h}h ${m}m` : `${m}m`;

    // API key status
    const apiKeyField = cfg["DEFAULT__apiKey"];
    const hasKey = apiKeyField && apiKeyField.value && apiKeyField.value.trim() !== "";
    document.getElementById("sched-apikey").innerHTML = hasKey
      ? `<span class="badge" style="background:var(--success)">Configured</span>`
      : `<span class="badge" style="background:var(--medium)">Not set — rate limited</span>`;

    _tickCountdown();
    if (_schedCountdownTimer) clearInterval(_schedCountdownTimer);
    _schedCountdownTimer = setInterval(_tickCountdown, 1000);
  } catch (e) { console.error("loadScheduleInfo:", e); }
}

function _tickCountdown() {
  if (!_schedInfo) return;
  const el = document.getElementById("sched-countdown");
  if (!el) return;
  const last = _schedInfo.last_finished || _schedInfo.last_scan;
  if (!last) { el.textContent = "—"; return; }
  const freq    = _schedInfo.check_frequency || 3600;
  const elapsed = (Date.now() - new Date(last).getTime()) / 1000;
  const remaining = Math.max(0, freq - elapsed);
  if (remaining === 0) { el.textContent = "Due now"; return; }
  const h = Math.floor(remaining / 3600);
  const m = Math.floor((remaining % 3600) / 60);
  const s = Math.floor(remaining % 60);
  el.textContent = h ? `${h}h ${String(m).padStart(2,"0")}m ${String(s).padStart(2,"0")}s`
                     : `${m}m ${String(s).padStart(2,"0")}s`;
}

// ── Per-CVE send actions (detail panel) ──────────────────────────────────────

async function _sendCve(channel) {
  if (!_detailRow) return;
  const msg = document.getElementById("detail-action-msg");
  msg.textContent = `Sending to ${channel}…`;
  msg.className = "form-msg";
  try {
    const r = await fetch(`${API}/api/cve/send`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({ channel, cve: _detailRow }),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = `Sent to ${channel}!`; msg.className = "form-msg ok"; }
    else       { msg.textContent = j.error || "Failed";   msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 3000);
}

document.getElementById("btn-detail-send-slack").addEventListener("click",   () => _sendCve("slack"));
document.getElementById("btn-detail-send-webhook").addEventListener("click", () => _sendCve("webhook"));
document.getElementById("btn-detail-send-jira").addEventListener("click",    () => _sendCve("jira"));
document.getElementById("btn-detail-send-snow").addEventListener("click",    () => _sendCve("servicenow"));

// ── Bulk actions ──────────────────────────────────────────────────────────────

let _selectedCves = new Set();

function _updateBulkBar() {
  const bar = document.getElementById("bulk-bar");
  const cnt = document.getElementById("bulk-count");
  if (_selectedCves.size > 0) {
    bar.style.display = "flex";
    cnt.textContent = `${_selectedCves.size} selected`;
  } else {
    bar.style.display = "none";
  }
}

document.getElementById("chk-select-all").addEventListener("change", e => {
  const checked = e.target.checked;
  document.querySelectorAll(".chk-row").forEach(chk => {
    chk.checked = checked;
    const cveId = chk.dataset.cve;
    if (checked) _selectedCves.add(cveId); else _selectedCves.delete(cveId);
  });
  _updateBulkBar();
});

document.getElementById("btn-bulk-clear").addEventListener("click", () => {
  _selectedCves.clear();
  document.querySelectorAll(".chk-row").forEach(c => { c.checked = false; });
  document.getElementById("chk-select-all").checked = false;
  _updateBulkBar();
});

document.getElementById("btn-bulk-reviewed").addEventListener("click", async () => {
  for (const cveId of _selectedCves) {
    await fetch(`${API}/api/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({ cve_id: cveId, reviewed: true, notes: "" }),
    }).catch(() => {});
  }
  _selectedCves.clear();
  _updateBulkBar();
  await renderBrowseResults();
});

document.getElementById("btn-bulk-watchlist").addEventListener("click", async () => {
  for (const cveId of _selectedCves) {
    const row = _browseRows.find(r => r.cve_id === cveId);
    await fetch(`${API}/api/watchlist`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({ cve_id: cveId, keyword: row?.keyword || "" }),
    }).catch(() => {});
  }
  _selectedCves.clear();
  _updateBulkBar();
});

document.getElementById("btn-bulk-export").addEventListener("click", () => {
  const selected = _browseRows.filter(r => _selectedCves.has(r.cve_id));
  if (!selected.length) return;
  const headers = ["cve_id","severity","cvss_score","epss_score","kev","keyword","publish_date","cwe","description"];
  const csv = [headers.join(","), ...selected.map(r =>
    headers.map(h => `"${String(r[h] ?? "").replace(/"/g,'""')}"`).join(",")
  )].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], {type:"text/csv"}));
  a.download = `cve_selected_${Date.now()}.csv`;
  a.click();
});

document.getElementById("btn-bulk-compare").addEventListener("click", () => {
  const selected = _browseRows.filter(r => _selectedCves.has(r.cve_id)).slice(0, 3);
  if (selected.length < 2) { alert("Select 2 or 3 CVEs to compare."); return; }
  openCompare(selected);
});

// ── CVE comparison view ───────────────────────────────────────────────────────

function openCompare(rows) {
  const grid = document.getElementById("compare-grid");
  grid.innerHTML = "";
  grid.style.gridTemplateColumns = `repeat(${rows.length}, 1fr)`;

  rows.forEach(row => {
    let refs = [];
    try { refs = JSON.parse(row.references_json || "[]"); } catch {}
    const col = document.createElement("div");
    col.className = "compare-col";
    col.innerHTML = `
      <h3>${escHtml(row.cve_id)}</h3>
      <dl class="dl">
        <dt>Severity</dt>  <dd>${sevBadge(row.severity)} ${scoreStr(row.cvss_score)}</dd>
        <dt>EPSS</dt>      <dd>${epssStr(row.epss_score)}</dd>
        <dt>KEV</dt>       <dd>${row.kev ? kevBadge(1) : "No"}</dd>
        <dt>Published</dt> <dd>${escHtml((row.publish_date||"").slice(0,10))}</dd>
        <dt>CWE</dt>       <dd>${escHtml(row.cwe||"—")}</dd>
        <dt>Keyword</dt>   <dd>${escHtml(row.keyword||"—")}</dd>
      </dl>
      <div class="desc" style="font-size:12px">${escHtml(row.description||"")}</div>
      ${refs.length ? `<div class="refs" style="margin-top:.5rem"><strong>Refs</strong><br>${refs.slice(0,3).map(u=>`<a href="${escHtml(u)}" target="_blank" rel="noopener" style="font-size:11px">${escHtml(u.slice(0,60))}…</a>`).join("")}</div>` : ""}
    `;
    grid.appendChild(col);
  });

  document.getElementById("compare-overlay").classList.remove("hidden");
}

document.getElementById("btn-compare-close").addEventListener("click", () => {
  document.getElementById("compare-overlay").classList.add("hidden");
});
document.getElementById("compare-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) e.currentTarget.classList.add("hidden");
});

// ── Quick filter chips ────────────────────────────────────────────────────────

document.querySelectorAll(".qf-chip").forEach(btn => {
  btn.addEventListener("click", () => {
    // Apply chip filters to browse bar and search
    const sev      = btn.dataset.sev;
    const epss     = btn.dataset.epss;
    const reviewed = btn.dataset.reviewed;

    if (sev !== undefined)      document.getElementById("br-severity").value = sev || "NONE";
    if (reviewed !== undefined) document.getElementById("br-reviewed").value  = reviewed || "";

    // For EPSS filter we do a client-side post-filter by storing it and re-rendering
    _qfEpssMin = epss ? parseFloat(epss) : null;

    doBrowseSearchPaged(0);
  });
});

let _qfEpssMin = null;

async function _origRenderBrowse() {
  await Promise.all([_loadReviewedMap(_browseRows), _loadTriageMap()]);

  const reviewFilter = document.getElementById("br-reviewed").value;
  let rows = _browseRows;
  if (reviewFilter === "reviewed")   rows = rows.filter(r => _reviewedMap[r.cve_id]);
  if (reviewFilter === "unreviewed") rows = rows.filter(r => !_reviewedMap[r.cve_id]);
  if (_qfEpssMin != null) rows = rows.filter(r => (r.epss_score || 0) >= _qfEpssMin);

  const today = new Date().toISOString().slice(0, 10);

  const tbody = document.getElementById("browse-tbody");
  tbody.innerHTML = "";
  rows.forEach((row) => {
    const reviewed = _reviewedMap[row.cve_id];
    const checked  = _selectedCves.has(row.cve_id);
    const triage   = _triageMap[row.cve_id];
    let triageCell = "";
    if (triage) {
      const breached = triage.due_date && triage.due_date < today
        && !["closed","mitigated","wont_fix","false_positive"].includes(triage.status);
      triageCell = `<span class="triage-badge triage-${triage.status}${breached ? " triage-breached" : ""}">${_triageLabel(triage.status)}</span>`;
      if (triage.assignee) triageCell += ` <span class="triage-assignee">${escHtml(triage.assignee)}</span>`;
    }
    const tr = document.createElement("tr");
    tr.className = `clickable${reviewed ? " row-reviewed" : ""}`;
    tr.dataset.cve = row.cve_id;
    tr.dataset.idx = rows.indexOf(row);
    tr.innerHTML = `
      <td><input type="checkbox" class="chk-row" data-cve="${escHtml(row.cve_id)}" ${checked ? "checked" : ""} /></td>
      <td><code>${escHtml(row.cve_id)}</code></td>
      <td>${sevBadge(row.severity)}${row.alerted_severity && row.alerted_severity !== (row.severity||"").toUpperCase() && row.alerted_severity !== row.severity ? ` <span class="badge-upgraded" title="Upgraded from ${escHtml(row.alerted_severity)}">⬆</span>` : ""}</td>
      <td class="num">${scoreStr(row.cvss_score)}</td>
      <td class="num">${epssStr(row.epss_score)}</td>
      <td>${kevBadge(row.kev)}</td>
      <td>${escHtml(row.keyword || "")}</td>
      <td>${escHtml((row.publish_date || "").slice(0, 10))}</td>
      <td>${reviewed ? `<span class="badge-reviewed">✓</span>` : ""}</td>
      <td>${triageCell}</td>
      <td>${escHtml(truncate(row.description, 90))}</td>
    `;
    // Checkbox toggle
    tr.querySelector(".chk-row").addEventListener("change", e => {
      e.stopPropagation();
      if (e.target.checked) _selectedCves.add(row.cve_id); else _selectedCves.delete(row.cve_id);
      _updateBulkBar();
    });
    tr.addEventListener("click", e => {
      if (e.target.type === "checkbox") return;
      _browseSelectedIdx = parseInt(tr.dataset.idx, 10);
      _updateBrowseHighlight();
      openDetail(row);
    });
    tbody.appendChild(tr);
  });
  _animateRows(tbody);
  document.getElementById("browse-status").textContent = `${rows.length} result(s) — click a row for detail`;
}

function _triageLabel(status) {
  return { open: "Open", investigating: "Investigating", mitigated: "Mitigated",
           wont_fix: "Won't Fix", false_positive: "FP", closed: "Closed" }[status] || status;
}

// ── Analytics ─────────────────────────────────────────────────────────────────

let _ageChart = null, _sevTimeChart = null, _scatterChart = null;

async function loadAnalytics() {
  await Promise.all([loadAgeChart(), loadSevTimeChart(), loadScatterChart(), loadHeatmap()]);
}

async function loadAgeChart() {
  try {
    const r = await fetch(`${API}/api/analytics/age`);
    const rows = await r.json();
    const ctx = document.getElementById("age-chart").getContext("2d");
    if (_ageChart) _ageChart.destroy();
    _ageChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: rows.map(r => r.label),
        datasets: [{ label: "CVEs", data: rows.map(r => r.count),
          backgroundColor: ["rgba(124,58,237,.8)","rgba(217,119,6,.8)","rgba(220,38,38,.7)","rgba(55,65,81,.7)"],
          borderRadius: 4 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94a3b8", font: { size: 11 } }, grid: { color: "#2d2d4e" } },
          y: { ticks: { color: "#94a3b8", font: { size: 11 } }, grid: { color: "#2d2d4e" } },
        },
      },
    });
  } catch (e) { console.error("loadAgeChart:", e); }
}

async function loadSevTimeChart() {
  try {
    const r = await fetch(`${API}/api/analytics/severity-over-time?limit=30`);
    const rows = await r.json();
    const ctx = document.getElementById("sev-time-chart").getContext("2d");
    if (_sevTimeChart) _sevTimeChart.destroy();
    _sevTimeChart = new Chart(ctx, {
      type: "line",
      data: {
        labels: rows.map(r => (r.started_at||"").slice(5,16)),
        datasets: [
          { label: "New",      data: rows.map(r => r.new_cves||0),     borderColor: "#7c3aed", backgroundColor: "rgba(124,58,237,.15)", fill: true, tension: .3, pointRadius: 3 },
          { label: "Upgraded", data: rows.map(r => r.updated_cves||0), borderColor: "#d97706", backgroundColor: "rgba(217,119,6,.1)",   fill: true, tension: .3, pointRadius: 3 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#94a3b8", font: { size: 11 } } } },
        scales: {
          x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#2d2d4e" } },
          y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#2d2d4e" } },
        },
      },
    });
  } catch (e) { console.error("loadSevTimeChart:", e); }
}

async function loadScatterChart() {
  try {
    const r = await fetch(`${API}/api/analytics/scatter?limit=500`);
    const rows = await r.json();
    // Split into KEV and non-KEV datasets
    const sevRadius = { CRITICAL: 8, HIGH: 6, MEDIUM: 4, LOW: 3 };
    const kevPts  = rows.filter(r => r.kev).map(r => ({ x: r.cvss_score, y: (r.epss_score||0)*100, r: sevRadius[r.severity]||4, label: r.cve_id }));
    const normPts = rows.filter(r => !r.kev).map(r => ({ x: r.cvss_score, y: (r.epss_score||0)*100, r: sevRadius[r.severity]||3, label: r.cve_id }));

    const ctx = document.getElementById("scatter-chart").getContext("2d");
    if (_scatterChart) _scatterChart.destroy();
    _scatterChart = new Chart(ctx, {
      type: "bubble",
      data: {
        datasets: [
          { label: "KEV",     data: kevPts,  backgroundColor: "rgba(147,51,234,.75)", borderColor: "#9333ea" },
          { label: "Non-KEV", data: normPts, backgroundColor: "rgba(99,102,241,.35)", borderColor: "rgba(99,102,241,.6)" },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: "#94a3b8", font: { size: 11 } } },
          tooltip: { callbacks: { label: ctx => `${ctx.raw.label || ""} CVSS:${ctx.raw.x} EPSS:${ctx.raw.y.toFixed(1)}%` } },
        },
        scales: {
          x: { title: { display: true, text: "CVSS Score", color: "#94a3b8" }, ticks: { color: "#94a3b8" }, grid: { color: "#2d2d4e" }, min: 0, max: 10 },
          y: { title: { display: true, text: "EPSS %",     color: "#94a3b8" }, ticks: { color: "#94a3b8" }, grid: { color: "#2d2d4e" }, min: 0 },
        },
      },
    });
  } catch (e) { console.error("loadScatterChart:", e); }
}

async function loadHeatmap() {
  try {
    const r = await fetch(`${API}/api/analytics/heatmap?days=90`);
    const rows = await r.json();
    const container = document.getElementById("heatmap-container");
    container.innerHTML = "";
    if (!rows.length) {
      container.innerHTML = '<span class="muted">No scan data yet.</span>';
      return;
    }
    const maxCount = Math.max(...rows.map(r => r.count), 1);
    // Build a date→count map
    const map = {};
    rows.forEach(r => { map[r.date] = r.count; });

    // Render last 90 days as a grid of day cells
    const today = new Date();
    const cells = [];
    for (let i = 89; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      const cnt = map[key] || 0;
      const intensity = cnt === 0 ? 0 : Math.max(0.15, cnt / maxCount);
      cells.push({ date: key, count: cnt, intensity });
    }

    cells.forEach(c => {
      const cell = document.createElement("div");
      cell.className = "heatmap-cell";
      cell.title = `${c.date}: ${c.count} new CVE${c.count !== 1 ? "s" : ""}`;
      cell.style.backgroundColor = c.intensity === 0
        ? "var(--surface2)"
        : `rgba(124,58,237,${c.intensity.toFixed(2)})`;
      container.appendChild(cell);
    });
  } catch (e) { console.error("loadHeatmap:", e); }
}

document.getElementById("btn-refresh-scatter").addEventListener("click", loadScatterChart);
document.getElementById("btn-refresh-heatmap").addEventListener("click", loadHeatmap);

// ── Notification log ──────────────────────────────────────────────────────────

async function loadNotifyLog() {
  try {
    const r = await fetch(`${API}/api/notify/log?limit=200`);
    const rows = await r.json();
    const tbody = document.getElementById("notifylog-tbody");
    tbody.innerHTML = "";
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="muted" style="padding:1rem">No notifications sent yet.</td></tr>`;
      return;
    }
    rows.forEach(row => {
      const ok = row.success;
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td>${escHtml((row.sent_at||"").slice(0,16))}</td>
          <td><span class="badge" style="background:var(--accent)">${escHtml(row.channel||"")}</span></td>
          <td>${escHtml(row.profile||"—")}</td>
          <td class="num">${row.cve_count ?? 0}</td>
          <td><small>${escHtml(truncate(row.recipients||"",40))}</small></td>
          <td>${ok ? `<span style="color:var(--success)">✓ OK</span>` : `<span style="color:var(--critical)">✗ Failed</span>`}</td>
          <td><small style="color:var(--critical)">${escHtml(truncate(row.error||"",50))}</small></td>
        </tr>
      `);
    });
  } catch (e) { console.error("loadNotifyLog:", e); }
}

// ── Triage detail save ────────────────────────────────────────────────────────

document.getElementById("btn-detail-triage-save").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg = document.getElementById("detail-action-msg");
  try {
    const r = await fetch(`${API}/api/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({
        cve_id:   _detailRow.cve_id,
        status:   document.getElementById("detail-triage-status").value,
        assignee: document.getElementById("detail-triage-assignee").value.trim(),
        due_date: document.getElementById("detail-triage-due").value,
        severity: _detailRow.severity || "",
      }),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = "Triage saved!"; msg.className = "form-msg ok"; }
    else       { msg.textContent = j.error || "Failed"; msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 2500);
});

// ── Suppress / false-positive ─────────────────────────────────────────────────

document.getElementById("btn-detail-suppress").addEventListener("click", async () => {
  if (!_detailRow) return;
  const reason = prompt(`Suppress ${_detailRow.cve_id}?\nEnter a reason (or leave blank):`);
  if (reason === null) return; // cancelled
  const msg = document.getElementById("detail-action-msg");
  try {
    const r = await fetch(`${API}/api/suppressions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({
        cve_id:  _detailRow.cve_id,
        keyword: _detailRow.keyword || "",
        reason,
      }),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = "CVE suppressed."; msg.className = "form-msg ok"; }
    else       { msg.textContent = j.error || "Failed"; msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 2500);
});

// ── CVSS vector breakdown ─────────────────────────────────────────────────────

async function _loadCvssVector(row) {
  const el = document.getElementById("cvss-vector-breakdown");
  el.style.display = "none";
  el.innerHTML = "";
  // Extract vector from cpe or references_json — NVD stores it in the raw data
  // We try the references for a CVSS vector string pattern
  let vector = "";
  try {
    const refs = JSON.parse(row.references_json || "[]");
    for (const ref of refs) {
      const m = ref.match(/CVSS:3\.[01]\/[A-Z:A-Z\/]+/);
      if (m) { vector = m[0]; break; }
    }
  } catch {}

  if (!vector) return;

  try {
    const r = await fetch(`${API}/api/cve/cvss-vector?v=${encodeURIComponent(vector)}`);
    const data = await r.json();
    if (!Object.keys(data).length) return;
    const cols = Object.entries(data).map(([k, v]) => `
      <div class="cvss-component">
        <div class="cvss-key">${escHtml(v.name)}</div>
        <div class="cvss-val cvss-${v.code}">${escHtml(v.label)}</div>
      </div>
    `).join("");
    el.innerHTML = `<div class="cvss-grid">${cols}</div>`;
    el.style.display = "";
  } catch {}
}

// ── Triage section ────────────────────────────────────────────────────────────

async function loadTriage() {
  const statusFilter = document.getElementById("triage-status-filter").value;
  try {
    const [triageRows, breachedRows] = await Promise.all([
      fetch(`${API}/api/triage${statusFilter ? "?status=" + statusFilter : ""}`).then(r => r.json()),
      fetch(`${API}/api/triage/sla/breached`).then(r => r.json()),
    ]);

    // SLA breach banner
    const banner = document.getElementById("sla-breach-banner");
    if (breachedRows.length) {
      banner.style.display = "";
      banner.innerHTML = `<strong>⚠ ${breachedRows.length} SLA breach${breachedRows.length > 1 ? "es" : ""}:</strong> ` +
        breachedRows.map(r => `<code>${escHtml(r.cve_id)}</code> (due ${escHtml(r.due_date)})`).join(", ");
    } else {
      banner.style.display = "none";
    }

    const tbody = document.getElementById("triage-tbody");
    const emptyEl = document.getElementById("triage-empty");
    tbody.innerHTML = "";
    if (!triageRows.length) {
      emptyEl.style.display = "";
      return;
    }
    emptyEl.style.display = "none";
    const today = new Date().toISOString().slice(0, 10);

    triageRows.forEach(row => {
      const breached = row.due_date && row.due_date < today
        && !["closed","mitigated","wont_fix","false_positive"].includes(row.status);
      const slaBadge = !row.due_date ? "—"
        : breached
          ? `<span class="sla-badge sla-breached">Breached (${escHtml(row.due_date)})</span>`
          : `<span class="sla-badge sla-ok">${escHtml(row.due_date)}</span>`;

      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td><code>${escHtml(row.cve_id)}</code></td>
          <td><span class="triage-badge triage-${row.status}">${_triageLabel(row.status)}</span></td>
          <td>${escHtml(row.assignee || "—")}</td>
          <td>${escHtml(row.due_date || "—")}</td>
          <td>${slaBadge}</td>
          <td>${escHtml((row.updated_at || "").slice(0, 16))}</td>
        </tr>
      `);
    });
    _animateRows(tbody);
  } catch (e) { console.error("loadTriage:", e); }

  loadSuppressions();
}

document.getElementById("triage-status-filter").addEventListener("change", loadTriage);
document.getElementById("btn-triage-refresh").addEventListener("click", loadTriage);

async function loadSuppressions() {
  try {
    const r = await fetch(`${API}/api/suppressions`);
    const rows = await r.json();
    const tbody = document.getElementById("suppression-tbody");
    const emptyEl = document.getElementById("suppression-empty");
    tbody.innerHTML = "";
    if (!rows.length) { emptyEl.style.display = ""; return; }
    emptyEl.style.display = "none";
    rows.forEach(row => {
      _suppressedIds.add(row.cve_id);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${escHtml(row.cve_id)}</code></td>
        <td>${escHtml(row.keyword || "—")}</td>
        <td>${escHtml(row.reason || "—")}</td>
        <td>${escHtml((row.suppressed_at || "").slice(0, 16))}</td>
        <td>${escHtml(row.suppressed_by || "—")}</td>
        <td><button class="btn-sm btn-suppression-remove" data-cve="${escHtml(row.cve_id)}">Restore</button></td>
      `;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll(".btn-suppression-remove").forEach(btn => {
      btn.addEventListener("click", async () => {
        await fetch(`${API}/api/suppressions/${encodeURIComponent(btn.dataset.cve)}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
        loadSuppressions();
      });
    });
  } catch (e) { console.error("loadSuppressions:", e); }
}

document.getElementById("btn-suppression-refresh").addEventListener("click", loadSuppressions);

// ── Saved views (server-side) ─────────────────────────────────────────────────

async function loadSavedViews() {
  try {
    const r = await fetch(`${API}/api/views`);
    const views = await r.json();
    const list = document.getElementById("saved-views-list");
    list.innerHTML = "";
    if (!views.length) {
      list.innerHTML = '<span class="muted">No saved views yet.</span>';
      return;
    }
    views.forEach(v => {
      const chip = document.createElement("span");
      chip.className = "search-chip";
      chip.innerHTML = `${escHtml(v.name)} <button class="chip-del" data-name="${escHtml(v.name)}">✕</button>`;
      chip.querySelector("button").addEventListener("click", async e => {
        e.stopPropagation();
        await fetch(`${API}/api/views/${encodeURIComponent(v.name)}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
        loadSavedViews();
      });
      chip.addEventListener("click", e => {
        if (e.target.tagName === "BUTTON") return;
        const f = v.filters || {};
        showSection("browse");
        loadBrowseTables(false).then(() => {
          if (f.table)    document.getElementById("br-table").value     = f.table;
          if (f.search)   document.getElementById("br-search").value    = f.search;
          if (f.severity) document.getElementById("br-severity").value  = f.severity;
          if (f.dateFrom) document.getElementById("br-date-from").value = f.dateFrom;
          if (f.dateTo)   document.getElementById("br-date-to").value   = f.dateTo;
          doBrowseSearchPaged(0);
        });
      });
      list.appendChild(chip);
    });
  } catch (e) { console.error("loadSavedViews:", e); }
}

document.getElementById("btn-save-view").addEventListener("click", async () => {
  const name = document.getElementById("saved-view-name").value.trim();
  if (!name) return;
  const msg  = document.getElementById("saved-view-msg");
  const filters = {
    table:    document.getElementById("br-table").value,
    search:   document.getElementById("br-search").value,
    severity: document.getElementById("br-severity").value,
    dateFrom: document.getElementById("br-date-from").value,
    dateTo:   document.getElementById("br-date-to").value,
  };
  try {
    const r = await fetch(`${API}/api/views`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({ name, filters }),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = "View saved!"; msg.className = "form-msg ok";
      document.getElementById("saved-view-name").value = "";
      loadSavedViews();
    } else {
      msg.textContent = j.error || "Failed"; msg.className = "form-msg err";
    }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 3000);
});

// ── Config validation ─────────────────────────────────────────────────────────

document.getElementById("btn-validate-config").addEventListener("click", async () => {
  const msg     = document.getElementById("validate-msg");
  const results = document.getElementById("validate-results");
  msg.textContent = "Testing…"; msg.className = "form-msg";
  results.style.display = "none";
  try {
    const r = await fetch(`${API}/api/config/validate`, { method: "POST", headers: { "X-CSRF-Token": _csrfToken() } });
    const data = await r.json();
    msg.textContent = "Done"; msg.className = "form-msg ok";
    results.style.display = "";
    results.innerHTML = Object.entries(data).map(([ch, v]) => {
      const icon = v.ok === true ? "✓" : v.ok === false ? "✗" : "—";
      const cls  = v.ok === true ? "validate-ok" : v.ok === false ? "validate-err" : "validate-na";
      return `<div class="validate-row"><span class="${cls}">${icon}</span><strong>${escHtml(ch)}</strong>${v.error ? `<span class="validate-detail">${escHtml(v.error)}</span>` : ""}</div>`;
    }).join("");
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 4000);
});

// ── Scan health panel ─────────────────────────────────────────────────────────

let _scanHealthChart = null;

async function loadScanHealth() {
  try {
    const r = await fetch(`${API}/api/scan/health?limit=20`);
    const d = await r.json();
    document.getElementById("health-success-rate").textContent = d.success_rate != null ? `${d.success_rate}%` : "—";
    document.getElementById("health-avg-dur").textContent      = d.avg_duration_sec ? `${d.avg_duration_sec}s` : "—";
    document.getElementById("health-error-rate").textContent   = d.error_rate != null ? `${d.error_rate}%` : "—";
    document.getElementById("health-total").textContent        = d.total ?? "—";

    // NVD API health
    const nvd      = d.nvd || {};
    const nvdEl    = document.getElementById("health-nvd-status");
    const staleBanner = document.getElementById("health-nvd-stale-banner");
    if (nvd.last_nvd_success) {
      const ago = Math.round((Date.now() - new Date(nvd.last_nvd_success).getTime()) / 60000);
      nvdEl.textContent = ago < 60 ? `${ago}m ago` : `${Math.round(ago/60)}h ago`;
      nvdEl.style.color = nvd.nvd_stale ? "var(--critical)" : "var(--success)";
    } else if (nvd.last_nvd_error) {
      nvdEl.textContent = "Error";
      nvdEl.style.color = "var(--critical)";
    } else {
      nvdEl.textContent = "No scan yet";
      nvdEl.style.color = "";
    }
    if (staleBanner) staleBanner.style.display = nvd.nvd_stale ? "" : "none";

    // Mini sparkline: new CVEs per scan
    const scans = d.scans || [];
    const labels = scans.map(s => (s.started_at || "").slice(5, 10));
    const values = scans.map(s => s.new_cves || 0);
    const colors = scans.map(s => s.error ? "rgba(220,38,38,.7)" : "rgba(124,58,237,.6)");

    const ctx = document.getElementById("scan-health-chart").getContext("2d");
    if (_scanHealthChart) _scanHealthChart.destroy();
    _scanHealthChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{ data: values, backgroundColor: colors, borderRadius: 2 }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: {
          callbacks: { label: ctx => {
            const s = scans[ctx.dataIndex];
            return s?.error ? `Error: ${s.error}` : `${ctx.raw} new CVEs`;
          }}
        }},
        scales: {
          x: { display: false },
          y: { display: false },
        },
      },
    });
  } catch (e) { console.error("loadScanHealth:", e); }
}

document.getElementById("btn-refresh-scan-health").addEventListener("click", loadScanHealth);

// ── Keyboard navigation in Browse ─────────────────────────────────────────────

let _browseSelectedIdx = -1;

function _updateBrowseHighlight() {
  document.querySelectorAll("#browse-tbody tr[data-idx]").forEach(tr => {
    tr.classList.toggle("kb-selected", parseInt(tr.dataset.idx, 10) === _browseSelectedIdx);
  });
}

function _getBrowseRows() {
  return Array.from(document.querySelectorAll("#browse-tbody tr[data-idx]"));
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────

document.getElementById("btn-shortcuts").addEventListener("click", () => {
  document.getElementById("shortcuts-overlay").classList.toggle("hidden");
});
document.getElementById("btn-shortcuts-close").addEventListener("click", () => {
  document.getElementById("shortcuts-overlay").classList.add("hidden");
});
document.getElementById("shortcuts-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) e.currentTarget.classList.add("hidden");
});

document.addEventListener("keydown", e => {
  // Ignore when typing in an input
  if (["INPUT","TEXTAREA","SELECT"].includes(e.target.tagName)) {
    if (e.key === "Escape") { e.target.blur(); return; }
    return;
  }

  const overlayOpen = !document.getElementById("detail-overlay").classList.contains("hidden")
                   || !document.getElementById("compare-overlay").classList.contains("hidden");

  if (e.key === "?") {
    e.preventDefault();
    document.getElementById("shortcuts-overlay").classList.toggle("hidden");
    return;
  }

  if (e.key === "/" && !overlayOpen) {
    e.preventDefault();
    showSection("browse");
    document.getElementById("br-search").focus();
    return;
  }

  if (overlayOpen) return;

  const browseActive = document.getElementById("section-browse").classList.contains("active");
  if (!browseActive) return;

  const trs = _getBrowseRows();
  if (!trs.length) return;

  if (e.key === "j" || e.key === "ArrowDown") {
    e.preventDefault();
    _browseSelectedIdx = Math.min(_browseSelectedIdx + 1, trs.length - 1);
    _updateBrowseHighlight();
    trs[_browseSelectedIdx]?.scrollIntoView({ block: "nearest" });
  } else if (e.key === "k" || e.key === "ArrowUp") {
    e.preventDefault();
    _browseSelectedIdx = Math.max(_browseSelectedIdx - 1, 0);
    _updateBrowseHighlight();
    trs[_browseSelectedIdx]?.scrollIntoView({ block: "nearest" });
  } else if ((e.key === "o" || e.key === "Enter") && _browseSelectedIdx >= 0) {
    e.preventDefault();
    const row = _browseRows[_browseSelectedIdx];
    if (row) openDetail(row);
  } else if (e.key === "w" && _browseSelectedIdx >= 0) {
    e.preventDefault();
    const row = _browseRows[_browseSelectedIdx];
    if (row) {
      fetch(`${API}/api/watchlist`, {
        method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
        body: JSON.stringify({ cve_id: row.cve_id, keyword: row.keyword || "" }),
      });
    }
  } else if (e.key === "r" && _browseSelectedIdx >= 0) {
    e.preventDefault();
    const row = _browseRows[_browseSelectedIdx];
    if (row) {
      const alreadyReviewed = !!_reviewedMap[row.cve_id];
      fetch(`${API}/api/review`, {
        method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
        body: JSON.stringify({ cve_id: row.cve_id, reviewed: !alreadyReviewed, notes: "" }),
      }).then(() => renderBrowseResults());
    }
  } else if (e.key === "s" && _browseSelectedIdx >= 0) {
    e.preventDefault();
    const row = _browseRows[_browseSelectedIdx];
    if (row) {
      if (_selectedCves.has(row.cve_id)) _selectedCves.delete(row.cve_id);
      else _selectedCves.add(row.cve_id);
      _updateBulkBar();
      _updateBrowseHighlight();
      const chk = trs[_browseSelectedIdx]?.querySelector(".chk-row");
      if (chk) chk.checked = _selectedCves.has(row.cve_id);
    }
  } else if (e.key >= "1" && e.key <= "6") {
    e.preventDefault();
    const chips = document.querySelectorAll(".qf-chip");
    const chip = chips[parseInt(e.key, 10) - 1];
    if (chip) chip.click();
  }
});

// ── Exploit intelligence ──────────────────────────────────────────────────────

async function _loadExploitIntel(row) {
  const panel   = document.getElementById("exploit-intel-panel");
  const content = document.getElementById("exploit-intel-content");
  panel.style.display = "";
  content.innerHTML = '<span class="muted">Loading…</span>';
  try {
    const r = await fetch(`${API}/api/exploit/${encodeURIComponent(row.cve_id)}`);
    const d = await r.json();
    if (!d || !d.cve_id) {
      content.innerHTML = '<span class="muted">No exploit data yet — click Check for Exploits.</span>';
      return;
    }
    const refs = (d.exploit_refs || []).map(u =>
      `<a href="${escHtml(u)}" target="_blank" rel="noopener" class="exploit-ref">${escHtml(u.slice(0, 70))}${u.length > 70 ? "…" : ""}</a>`
    ).join("");
    const badge = d.has_exploit
      ? `<span class="badge badge-CRITICAL">PoC / Exploit Known</span>`
      : `<span class="badge" style="background:var(--surface3);color:var(--text2)">No known exploit</span>`;
    content.innerHTML = `
      <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem">
        ${badge}
        <span class="muted" style="font-size:11px">Source: ${escHtml(d.source || "unknown")} · Checked: ${escHtml((d.checked_at||"").slice(0,16))}</span>
      </div>
      ${refs ? `<div class="exploit-refs-list">${refs}</div>` : ""}
    `;
  } catch { content.innerHTML = '<span class="muted">Failed to load.</span>'; }
}

document.getElementById("btn-detail-enrich-exploit").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg = document.getElementById("exploit-enrich-msg");
  const btn = document.getElementById("btn-detail-enrich-exploit");
  btn.disabled = true;
  msg.textContent = "Searching…"; msg.className = "form-msg";
  try {
    const r = await fetch(`${API}/api/exploit/enrich/${encodeURIComponent(_detailRow.cve_id)}`, { method: "POST", headers: { "X-CSRF-Token": _csrfToken() } });
    const d = await r.json();
    msg.textContent = d.has_exploit ? `Found ${d.exploit_refs.length} reference(s)!` : "No exploits found.";
    msg.className = d.has_exploit ? "form-msg ok" : "form-msg";
    await _loadExploitIntel(_detailRow);
  } catch { msg.textContent = "Search failed"; msg.className = "form-msg err"; }
  btn.disabled = false;
  setTimeout(() => { msg.textContent = ""; }, 4000);
});

// ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────

async function _loadAttackMapping(row) {
  const panel   = document.getElementById("attack-panel");
  const content = document.getElementById("attack-content");
  if (!row.cwe) { panel.style.display = "none"; return; }
  try {
    const r = await fetch(`${API}/api/attack/map?cwe=${encodeURIComponent(row.cwe)}`);
    const techs = await r.json();
    if (!techs.length) { panel.style.display = "none"; return; }
    panel.style.display = "";
    content.innerHTML = techs.map(t => `
      <span class="attack-chip" title="CWE: ${escHtml(t.cwe)}">
        <a href="https://attack.mitre.org/techniques/${escHtml(t.id.replace(".","/"))}" target="_blank" rel="noopener">
          <span class="attack-id">${escHtml(t.id)}</span>
          <span class="attack-name">${escHtml(t.name)}</span>
        </a>
        <span class="attack-tactic">${escHtml(t.tactic)}</span>
      </span>
    `).join("");
  } catch { panel.style.display = "none"; }
}

// ── Affected assets correlation ───────────────────────────────────────────────

async function _loadAffectedAssets(row) {
  const panel   = document.getElementById("affected-assets-panel");
  const content = document.getElementById("affected-assets-content");
  if (!row.cpe) { panel.style.display = "none"; return; }
  try {
    const r = await fetch(`${API}/api/assets/match?cpe=${encodeURIComponent(row.cpe)}`);
    const assets = await r.json();
    if (!assets.length) { panel.style.display = "none"; return; }
    panel.style.display = "";
    content.innerHTML = assets.map(a => `
      <span class="asset-chip env-${escHtml((a.environment||"other").toLowerCase())}">
        <strong>${escHtml(a.name)}</strong>
        ${a.environment ? `<span class="asset-env">${escHtml(a.environment)}</span>` : ""}
        ${a.owner ? `<span class="asset-owner">${escHtml(a.owner)}</span>` : ""}
      </span>
    `).join("");
  } catch { panel.style.display = "none"; }
}

// ── Related CVEs (chaining) ───────────────────────────────────────────────────

async function _loadRelatedCves(row) {
  const panel   = document.getElementById("related-cves-panel");
  const content = document.getElementById("related-cves-content");
  if (!row.cwe && !row.cpe) { panel.style.display = "none"; return; }
  try {
    const params = new URLSearchParams({ cve_id: row.cve_id, limit: 8 });
    if (row.cwe) params.set("cwe", row.cwe);
    if (row.cpe) params.set("cpe", row.cpe);
    const r = await fetch(`${API}/api/cve/related?${params}`);
    const rows = await r.json();
    if (!rows.length) { panel.style.display = "none"; return; }
    panel.style.display = "";
    content.innerHTML = `<div class="related-cves-list">${rows.map(rc => `
      <div class="related-cve-row clickable" data-cve="${escHtml(rc.cve_id)}" data-kw="${escHtml(rc._keyword||rc.keyword||"")}">
        <code>${escHtml(rc.cve_id)}</code>
        ${sevBadge(rc.severity)}
        <span class="num">${scoreStr(rc.cvss_score)}</span>
        <span class="muted" style="font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(rc.description, 60))}</span>
      </div>
    `).join("")}</div>`;
    content.querySelectorAll(".related-cve-row").forEach(el => {
      el.addEventListener("click", () => openDetail(rows.find(r => r.cve_id === el.dataset.cve) || rows[0]));
    });
  } catch { panel.style.display = "none"; }
}

// ── Internal CVSS override ────────────────────────────────────────────────────

async function _loadCvssOverride(row) {
  try {
    const r = await fetch(`${API}/api/cvss-override/${encodeURIComponent(row.cve_id)}`);
    const d = await r.json();
    document.getElementById("detail-override-score").value     = d.internal_score != null ? d.internal_score : "";
    document.getElementById("detail-override-sev").value       = d.internal_sev   || "";
    document.getElementById("detail-override-rationale").value = d.rationale      || "";
  } catch {
    document.getElementById("detail-override-score").value     = "";
    document.getElementById("detail-override-sev").value       = "";
    document.getElementById("detail-override-rationale").value = "";
  }
}

document.getElementById("btn-detail-override-save").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg   = document.getElementById("detail-override-msg");
  const score = document.getElementById("detail-override-score").value;
  try {
    const r = await fetch(`${API}/api/cvss-override`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({
        cve_id:         _detailRow.cve_id,
        internal_score: score !== "" ? parseFloat(score) : null,
        internal_sev:   document.getElementById("detail-override-sev").value,
        rationale:      document.getElementById("detail-override-rationale").value,
        overridden_by:  "",
      }),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = "Override saved!"; msg.className = "form-msg ok"; }
    else       { msg.textContent = j.error || "Failed"; msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 2500);
});

document.getElementById("btn-detail-override-clear").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg = document.getElementById("detail-override-msg");
  try {
    await fetch(`${API}/api/cvss-override/${encodeURIComponent(_detailRow.cve_id)}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
    document.getElementById("detail-override-score").value     = "";
    document.getElementById("detail-override-sev").value       = "";
    document.getElementById("detail-override-rationale").value = "";
    msg.textContent = "Override cleared."; msg.className = "form-msg ok";
  } catch { msg.textContent = "Failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 2500);
});

// ── Patch tracking ────────────────────────────────────────────────────────────

async function _loadPatchInfo(row) {
  try {
    const r = await fetch(`${API}/api/triage/${encodeURIComponent(row.cve_id)}`);
    const d = await r.json();
    document.getElementById("detail-patch-version").value = d.patched_version || "";
    document.getElementById("detail-patch-date").value    = d.patched_at      || "";
    document.getElementById("detail-patch-by").value      = d.patched_by      || "";
  } catch {
    document.getElementById("detail-patch-version").value = "";
    document.getElementById("detail-patch-date").value    = "";
    document.getElementById("detail-patch-by").value      = "";
  }
}

document.getElementById("btn-detail-patch-save").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg     = document.getElementById("detail-patch-msg");
  const version = document.getElementById("detail-patch-version").value.trim();
  try {
    const r = await fetch(`${API}/api/triage/${encodeURIComponent(_detailRow.cve_id)}/patch`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({
        patched_version: version,
        patched_at:      document.getElementById("detail-patch-date").value,
        patched_by:      document.getElementById("detail-patch-by").value.trim(),
      }),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = "Patch info saved!"; msg.className = "form-msg ok";
      // Offer to auto-suppress future alerts now that a patch exists
      if (version && !_suppressedIds.has(_detailRow.cve_id)) {
        const suppress = confirm(
          `${_detailRow.cve_id} is marked as patched (${version}).\n\nAlso suppress future alerts for this CVE?`
        );
        if (suppress) {
          await fetch(`${API}/api/suppressions`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
            body: JSON.stringify({
              cve_id:  _detailRow.cve_id,
              keyword: _detailRow.keyword || "",
              reason:  `Patched: ${version}`,
            }),
          });
          _suppressedIds.add(_detailRow.cve_id);
          msg.textContent = "Patch saved + suppressed."; msg.className = "form-msg ok";
        }
      }
    } else {
      msg.textContent = j.error || "Failed"; msg.className = "form-msg err";
    }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 3000);
});


// ── Extend openDetail to load new panels ─────────────────────────────────────
// Wrap the existing openDetail so new panels load alongside the existing ones.

const _origOpenDetail = openDetail;
openDetail = async function(row) {
  await _origOpenDetail(row);
  await Promise.allSettled([
    _loadExploitIntel(row),
    _loadAttackMapping(row),
    _loadAffectedAssets(row),
    _loadRelatedCves(row),
    _loadCvssOverride(row),
    _loadPatchInfo(row),
  ]);
};

// ── Asset management ──────────────────────────────────────────────────────────

let _editingAsset = null;

function _openAssetEditor(asset = null) {
  _editingAsset = asset || null;
  document.getElementById("asset-editor-title").textContent = asset ? `Edit — ${escHtml(asset.name)}` : "New Asset";
  document.getElementById("asset-edit-id").value   = asset?.id || "";
  document.getElementById("asset-name").value      = asset?.name || "";
  document.getElementById("asset-cpe").value       = asset?.cpe  || "";
  document.getElementById("asset-env").value       = asset?.environment || "production";
  document.getElementById("asset-owner").value     = asset?.owner || "";
  document.getElementById("asset-tags").value      = asset?.tags  || "";
  document.getElementById("btn-asset-delete").style.display = asset ? "" : "none";
  document.getElementById("asset-msg").textContent = "";
  document.getElementById("asset-editor").classList.add("visible");
}

function _closeAssetEditor() {
  _editingAsset = null;
  document.getElementById("asset-editor").classList.remove("visible");
}

async function loadAssets() {
  try {
    const r    = await fetch(`${API}/api/assets`);
    const rows = await r.json();
    const tbody   = document.getElementById("assets-tbody");
    const emptyEl = document.getElementById("assets-empty");
    tbody.innerHTML = "";
    if (!rows.length) { emptyEl.style.display = ""; return; }
    emptyEl.style.display = "none";
    rows.forEach(a => {
      const tr = document.createElement("tr");
      tr.className = "clickable";
      tr.innerHTML = `
        <td><strong>${escHtml(a.name)}</strong></td>
        <td><span class="asset-env-badge env-${escHtml((a.environment||"other").toLowerCase())}">${escHtml(a.environment||"—")}</span></td>
        <td>${escHtml(a.owner||"—")}</td>
        <td><small>${escHtml(a.tags||"—")}</small></td>
        <td><small class="muted">${escHtml(truncate(a.cpe||"—", 60))}</small></td>
        <td><button class="btn-sm">Edit</button></td>
      `;
      tr.querySelector("button").addEventListener("click", e => { e.stopPropagation(); _openAssetEditor(a); });
      tr.addEventListener("click", () => _openAssetEditor(a));
      tbody.appendChild(tr);
    });
  } catch (e) { console.error("loadAssets:", e); }
}

document.getElementById("btn-asset-new").addEventListener("click", () => _openAssetEditor());
document.getElementById("btn-asset-cancel").addEventListener("click", _closeAssetEditor);

document.getElementById("btn-asset-save").addEventListener("click", async () => {
  const msg  = document.getElementById("asset-msg");
  const name = document.getElementById("asset-name").value.trim();
  if (!name) { msg.textContent = "Name is required."; msg.className = "form-msg err"; return; }
  const body = {
    name,
    cpe:         document.getElementById("asset-cpe").value.trim(),
    environment: document.getElementById("asset-env").value,
    owner:       document.getElementById("asset-owner").value.trim(),
    tags:        document.getElementById("asset-tags").value.trim(),
  };
  const editId = document.getElementById("asset-edit-id").value;
  if (editId) body.id = parseInt(editId, 10);
  try {
    const r = await fetch(`${API}/api/assets`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = "Saved!"; msg.className = "form-msg ok"; loadAssets(); setTimeout(_closeAssetEditor, 600); }
    else { msg.textContent = j.error || "Failed"; msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
});

document.getElementById("btn-asset-delete").addEventListener("click", async () => {
  if (!_editingAsset) return;
  if (!confirm(`Delete asset "${_editingAsset.name}"?`)) return;
  await fetch(`${API}/api/assets/${_editingAsset.id}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
  loadAssets();
  _closeAssetEditor();
});

// ── Scanner output import ─────────────────────────────────────────────────────

(function () {
  const toggle  = document.getElementById("scanner-import-toggle");
  const body    = document.getElementById("scanner-import-body");
  const chevron = document.getElementById("scanner-import-chevron");
  toggle.addEventListener("click", () => {
    const open = body.style.display !== "none";
    body.style.display    = open ? "none" : "";
    chevron.textContent   = open ? "▼ Expand" : "▲ Collapse";
  });

  const dropZone = document.getElementById("scanner-drop-zone");
  const textarea = document.getElementById("scanner-import-text");
  const fileInput = document.getElementById("scanner-import-file");

  dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.style.borderColor = "var(--accent)"; });
  dropZone.addEventListener("dragleave", () => { dropZone.style.borderColor = ""; });
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.style.borderColor = "";
    const file = e.dataTransfer.files[0];
    if (file) _readFile(file);
  });
  fileInput.addEventListener("change", () => { if (fileInput.files[0]) _readFile(fileInput.files[0]); });

  function _readFile(file) {
    const reader = new FileReader();
    reader.onload = ev => { textarea.value = ev.target.result; };
    reader.readAsText(file);
  }

  document.getElementById("btn-scanner-import").addEventListener("click", _doImport);

  async function _doImport() {
    const msg  = document.getElementById("scanner-import-msg");
    const raw  = textarea.value.trim();
    if (!raw) { msg.textContent = "Nothing to import."; msg.className = "form-msg err"; return; }

    const assetName = document.getElementById("import-asset-name").value.trim();
    const env       = document.getElementById("import-asset-env").value;
    const owner     = document.getElementById("import-asset-owner").value.trim();
    const tags      = document.getElementById("import-asset-tags").value.trim();

    msg.textContent = "Importing…"; msg.className = "form-msg";

    let keywords = [];
    let cpes     = [];

    // Detect JSON (scan_environment.py --json) vs plain keyword list
    if (raw.startsWith("[") || raw.startsWith("{")) {
      try {
        const parsed = JSON.parse(raw);
        const items  = Array.isArray(parsed) ? parsed : (parsed.items || parsed.software || []);
        items.forEach(item => {
          if (item.name) {
            const ver = item.version ? ` ${item.version.split(".").slice(0, 2).join(".")}` : "";
            const sev = item.severity_hint || "HIGH";
            keywords.push(`${item.name}${ver}::${sev}`);
          }
          if (item.cpe) cpes.push(item.cpe);
        });
      } catch {
        msg.textContent = "Invalid JSON."; msg.className = "form-msg err"; return;
      }
    } else {
      // Plain keyword list — one entry per line, skip blank/comment lines
      keywords = raw.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
      // Extract any CPE strings embedded in the output
      raw.split("\n").forEach(l => { const m = l.match(/cpe:2\.3:[^\s]+/); if (m) cpes.push(m[0]); });
    }

    if (!keywords.length) { msg.textContent = "No keywords found in input."; msg.className = "form-msg err"; return; }

    try {
      // 1. Create/update asset if a name was provided
      if (assetName) {
        const existing = await (await fetch(`${API}/api/assets`)).json();
        const found    = existing.find(a => a.name.toLowerCase() === assetName.toLowerCase());
        const body     = {
          name: assetName, environment: env,
          ...(owner && { owner }),
          ...(tags  && { tags }),
          ...(cpes.length && { cpe: [...new Set(cpes)].join(",") }),
          last_scanned_at: new Date().toISOString(),
          scan_source: "dashboard-import",
        };
        if (found) body.id = found.id;
        await fetch(`${API}/api/assets`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
          body: JSON.stringify(body),
        });
        loadAssets();
      }

      // 2. Merge keywords — fetch existing, dedup by product name (scanner wins on version)
      const cfgR    = await fetch(`${API}/api/config`);
      const cfg     = await cfgR.json();
      const existing = (cfg.keywords || "").split("\n").map(l => l.trim()).filter(Boolean);
      const existMap = {};
      existing.forEach(k => {
        const base = k.split("::")[0].replace(/\s+\d[\d.]*$/, "").trim().toLowerCase();
        existMap[base] = k;
      });
      keywords.forEach(k => {
        const base = k.split("::")[0].replace(/\s+\d[\d.]*$/, "").trim().toLowerCase();
        existMap[base] = k;
      });
      const merged = Object.values(existMap).sort();

      await fetch(`${API}/api/config`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
        body: JSON.stringify({ DEFAULT__keywords: merged.join("\n") }),
      });

      msg.textContent = `Imported ${keywords.length} keyword${keywords.length !== 1 ? "s" : ""}${assetName ? `, asset "${assetName}" saved` : ""}. Triggering scan…`;
      msg.className   = "form-msg ok";
      textarea.value  = "";

      // Auto-trigger a scan so new keywords are picked up immediately
      try {
        await fetch(`${API}/api/scan`, { method: "POST", headers: { "X-CSRF-Token": _csrfToken() } });
        msg.textContent = msg.textContent.replace("Triggering scan…", "Scan started.");
      } catch {
        msg.textContent = msg.textContent.replace("Triggering scan…", "");
      }
    } catch (e) {
      msg.textContent = `Import failed: ${e.message}`;
      msg.className   = "form-msg err";
    }
  }
})();

// ── User management (RBAC) ────────────────────────────────────────────────────

let _editingUser = null;

function _openUserEditor(user = null) {
  _editingUser = user || null;
  document.getElementById("user-editor-title").textContent = user ? `Edit — ${escHtml(user.username)}` : "New User";
  document.getElementById("user-username").value   = user?.username || "";
  document.getElementById("user-username").disabled = !!user;
  document.getElementById("user-role").value       = user?.role || "analyst";
  document.getElementById("user-email").value      = user?.email || "";
  document.getElementById("btn-user-delete").style.display = user ? "" : "none";
  document.getElementById("btn-user-save").textContent     = user ? "Update user" : "Create user";
  document.getElementById("user-msg").textContent  = "";
  document.getElementById("user-key-display").style.display = "none";
  document.getElementById("user-editor").classList.add("visible");
}

function _closeUserEditor() {
  _editingUser = null;
  document.getElementById("user-editor").classList.remove("visible");
}

async function loadUsers() {
  try {
    const r    = await fetch(`${API}/api/users`);
    if (r.status === 401 || r.status === 403) {
      document.getElementById("users-tbody").innerHTML =
        `<tr><td colspan="6" class="muted" style="padding:.75rem">Requires lead role or API_SECRET to view users.</td></tr>`;
      document.getElementById("users-empty").style.display = "none";
      return;
    }
    const rows = await r.json();
    const tbody   = document.getElementById("users-tbody");
    const emptyEl = document.getElementById("users-empty");
    tbody.innerHTML = "";
    if (!rows.length) { emptyEl.style.display = ""; return; }
    emptyEl.style.display = "none";
    rows.forEach(u => {
      const tr = document.createElement("tr");
      tr.className = "clickable";
      tr.innerHTML = `
        <td><strong>${escHtml(u.username)}</strong></td>
        <td><span class="role-badge role-${escHtml(u.role)}">${escHtml(u.role)}</span></td>
        <td>${escHtml(u.email || "—")}</td>
        <td>${escHtml((u.created_at || "").slice(0, 10))}</td>
        <td>${u.active ? '<span style="color:var(--success)">✓</span>' : '<span class="muted">Revoked</span>'}</td>
        <td><button class="btn-sm">Edit</button></td>
      `;
      tr.querySelector("button").addEventListener("click", e => { e.stopPropagation(); _openUserEditor(u); });
      tr.addEventListener("click", () => _openUserEditor(u));
      tbody.appendChild(tr);
    });
  } catch (e) { console.error("loadUsers:", e); }
}

document.getElementById("btn-user-new").addEventListener("click", () => _openUserEditor());
document.getElementById("btn-user-cancel").addEventListener("click", _closeUserEditor);

document.getElementById("btn-user-save").addEventListener("click", async () => {
  const msg  = document.getElementById("user-msg");
  const keyDisplay = document.getElementById("user-key-display");
  keyDisplay.style.display = "none";

  if (_editingUser) {
    // Update existing user
    try {
      const r = await fetch(`${API}/api/users/${encodeURIComponent(_editingUser.username)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
        body: JSON.stringify({
          role:  document.getElementById("user-role").value,
          email: document.getElementById("user-email").value.trim(),
        }),
      });
      const j = await r.json();
      if (j.ok) { msg.textContent = "Updated!"; msg.className = "form-msg ok"; loadUsers(); setTimeout(_closeUserEditor, 600); }
      else { msg.textContent = j.error || "Failed"; msg.className = "form-msg err"; }
    } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
    return;
  }

  // Create new user
  const username = document.getElementById("user-username").value.trim();
  if (!username) { msg.textContent = "Username is required."; msg.className = "form-msg err"; return; }
  try {
    const r = await fetch(`${API}/api/users`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({
        username,
        role:  document.getElementById("user-role").value,
        email: document.getElementById("user-email").value.trim(),
      }),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = "User created!"; msg.className = "form-msg ok";
      loadUsers();
      // Show the API key — it won't be retrievable later
      document.getElementById("user-key-value").textContent = j.api_key;
      keyDisplay.style.display = "";
    } else {
      msg.textContent = j.error || "Failed"; msg.className = "form-msg err";
    }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
});

document.getElementById("btn-user-delete").addEventListener("click", async () => {
  if (!_editingUser) return;
  if (!confirm(`Revoke access for "${_editingUser.username}"? They will not be able to authenticate.`)) return;
  await fetch(`${API}/api/users/${encodeURIComponent(_editingUser.username)}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
  loadUsers();
  _closeUserEditor();
});

document.getElementById("btn-copy-key").addEventListener("click", () => {
  const key = document.getElementById("user-key-value").textContent;
  navigator.clipboard.writeText(key).then(() => {
    document.getElementById("btn-copy-key").textContent = "Copied!";
    setTimeout(() => { document.getElementById("btn-copy-key").textContent = "Copy"; }, 2000);
  });
});

// ── SLA escalation ────────────────────────────────────────────────────────────

document.getElementById("btn-sla-escalate").addEventListener("click", async () => {
  const msg = document.getElementById("sla-escalate-msg");
  msg.textContent = "Sending SLA alerts…"; msg.className = "form-msg";
  try {
    const r = await fetch(`${API}/api/sla/escalate`, { method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({ hours: 24 }) });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = j.sent > 0
        ? `Sent ${j.sent} escalation alert(s).`
        : j.message || "No items require escalation.";
      msg.className = j.sent > 0 ? "form-msg ok" : "form-msg";
    } else {
      msg.textContent = j.error || "Failed"; msg.className = "form-msg err";
    }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
  setTimeout(() => { msg.textContent = ""; }, 6000);
});

// ── Update triage table to show patch info ────────────────────────────────────
// Patch the loadTriage function to add the Patched column

const _origLoadTriage = loadTriage;
loadTriage = async function() {
  const statusFilter = document.getElementById("triage-status-filter").value;
  try {
    const [triageRows, breachedRows] = await Promise.all([
      fetch(`${API}/api/triage${statusFilter ? "?status=" + statusFilter : ""}`).then(r => r.json()),
      fetch(`${API}/api/triage/sla/breached`).then(r => r.json()),
    ]);

    const banner = document.getElementById("sla-breach-banner");
    if (breachedRows.length) {
      banner.style.display = "";
      banner.innerHTML = `<strong>⚠ ${breachedRows.length} SLA breach${breachedRows.length > 1 ? "es" : ""}:</strong> ` +
        breachedRows.map(r => `<code>${escHtml(r.cve_id)}</code> (due ${escHtml(r.due_date)})`).join(", ");
    } else {
      banner.style.display = "none";
    }

    const tbody   = document.getElementById("triage-tbody");
    const emptyEl = document.getElementById("triage-empty");
    tbody.innerHTML = "";
    if (!triageRows.length) { emptyEl.style.display = ""; return; }
    emptyEl.style.display = "none";
    const today = new Date().toISOString().slice(0, 10);

    triageRows.forEach(row => {
      const breached = row.due_date && row.due_date < today
        && !["closed","mitigated","wont_fix","false_positive"].includes(row.status);
      const slaBadge = !row.due_date ? "—"
        : breached
          ? `<span class="sla-badge sla-breached">Breached (${escHtml(row.due_date)})</span>`
          : `<span class="sla-badge sla-ok">${escHtml(row.due_date)}</span>`;

      const patchedCell = row.patched_version
        ? `<span class="patch-badge">${escHtml(row.patched_version)}</span>${row.patched_at ? ` <span class="muted" style="font-size:11px">${escHtml(row.patched_at.slice(0,10))}</span>` : ""}`
        : "—";

      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td><code>${escHtml(row.cve_id)}</code></td>
          <td><span class="triage-badge triage-${row.status}">${_triageLabel(row.status)}</span></td>
          <td>${escHtml(row.assignee || "—")}</td>
          <td>${escHtml(row.due_date || "—")}</td>
          <td>${slaBadge}</td>
          <td>${patchedCell}</td>
          <td>${escHtml((row.updated_at || "").slice(0, 16))}</td>
        </tr>
      `);
    });
  } catch (e) { console.error("loadTriage:", e); }

  loadSuppressions();
};

// Re-bind the triage section controls to the new function
document.getElementById("triage-status-filter").removeEventListener("change", _origLoadTriage);
document.getElementById("btn-triage-refresh").removeEventListener("click", _origLoadTriage);
document.getElementById("triage-status-filter").addEventListener("change", loadTriage);
document.getElementById("btn-triage-refresh").addEventListener("click", loadTriage);

// ── Threat intelligence panel (detail overlay) ───────────────────────────────

async function _loadThreatIntel(row) {
  const panel   = document.getElementById("threat-intel-panel");
  const content = document.getElementById("threat-intel-content");
  panel.style.display = "";
  content.innerHTML = '<span class="muted">Loading…</span>';
  try {
    const r = await fetch(`${API}/api/threat/${encodeURIComponent(row.cve_id)}`);
    const d = await r.json();
    if (!d || !d.cve_id) {
      content.innerHTML = '<span class="muted">No threat intel yet — click Fetch Threat Data.</span>';
      return;
    }
    const badge = d.in_wild
      ? `<span class="badge badge-CRITICAL">In The Wild</span>`
      : `<span class="badge" style="background:#374151">Not Observed</span>`;
    const mfList  = (d.malware_families || []).map(m => `<span class="threat-chip threat-malware">${escHtml(m)}</span>`).join("");
    const campList = (d.campaigns || []).map(c => `<span class="threat-chip threat-campaign">${escHtml(c)}</span>`).join("");
    content.innerHTML = `
      <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.4rem">
        ${badge}
        <span class="muted" style="font-size:11px">Source: ${escHtml(d.source||"unknown")}</span>
      </div>
      ${mfList ? `<div style="margin-bottom:.3rem"><span class="detail-chip-label">Malware:</span> ${mfList}</div>` : ""}
      ${campList ? `<div><span class="detail-chip-label">Campaigns:</span> ${campList}</div>` : ""}
    `;
  } catch { content.innerHTML = '<span class="muted">Failed to load.</span>'; }
}

document.getElementById("btn-detail-enrich-threat").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg = document.getElementById("threat-enrich-msg");
  const btn = document.getElementById("btn-detail-enrich-threat");
  btn.disabled = true;
  msg.textContent = "Fetching…"; msg.className = "form-msg";
  try {
    const r = await fetch(`${API}/api/threat/enrich/${encodeURIComponent(_detailRow.cve_id)}`, { method: "POST", headers: { "X-CSRF-Token": _csrfToken() } });
    const d = await r.json();
    msg.textContent = d.in_wild ? "In-the-wild exploitation confirmed!" : "No active threat data found.";
    msg.className = d.in_wild ? "form-msg ok" : "form-msg";
    await _loadThreatIntel(_detailRow);
  } catch { msg.textContent = "Fetch failed"; msg.className = "form-msg err"; }
  btn.disabled = false;
  setTimeout(() => { msg.textContent = ""; }, 4000);
});

// ── Risk score panel (detail overlay) ────────────────────────────────────────

async function _loadRiskScore(row) {
  const panel   = document.getElementById("risk-score-panel");
  const content = document.getElementById("risk-score-content");
  try {
    const params = new URLSearchParams({ table: row._table || row.keyword || "" });
    const r = await fetch(`${API}/api/risk/${encodeURIComponent(row.cve_id)}?${params}`);
    if (!r.ok) { panel.style.display = "none"; return; }
    const d = await r.json();
    if (!d || d.score == null) { panel.style.display = "none"; return; }
    panel.style.display = "";
    const pct = d.score;
    const color = pct >= 80 ? "var(--critical)" : pct >= 60 ? "var(--high)" : pct >= 40 ? "var(--medium)" : "var(--low)";
    const f = d.factors || {};
    content.innerHTML = `
      <div style="display:flex;align-items:center;gap:1rem;margin-bottom:.5rem">
        <div style="font-size:28px;font-weight:800;color:${color}">${pct}</div>
        <div>
          <div style="font-weight:600;color:${color}">${escHtml(d.label)}</div>
          <div class="muted" style="font-size:11px">out of 100</div>
        </div>
        <div class="risk-bar-wrap">
          <div class="risk-bar" style="width:${pct}%;background:${color}"></div>
        </div>
      </div>
      <div class="risk-factors">
        ${Object.entries(f).map(([k,v]) => `
          <div class="risk-factor">
            <span class="risk-factor-label">${escHtml(k)}</span>
            <span class="risk-factor-val">${v}</span>
          </div>
        `).join("")}
      </div>
    `;
  } catch { panel.style.display = "none"; }
}

// ── Compliance panel (detail overlay) ────────────────────────────────────────

async function _loadCompliance(row) {
  const panel   = document.getElementById("compliance-panel");
  const content = document.getElementById("compliance-content");
  if (!row.cwe) { panel.style.display = "none"; return; }
  try {
    const r = await fetch(`${API}/api/compliance/map?cwe=${encodeURIComponent(row.cwe)}`);
    const d = await r.json();
    const nist = d.nist_800_53 || [];
    const cis  = d.cis_v8 || [];
    const iso  = d.iso_27001 || [];
    if (!nist.length && !cis.length && !iso.length) { panel.style.display = "none"; return; }
    panel.style.display = "";
    const chips = (arr, cls) => arr.map(c => `<span class="compliance-chip ${cls}">${escHtml(c)}</span>`).join("");
    content.innerHTML = `
      ${nist.length ? `<div class="compliance-row"><span class="compliance-label">NIST 800-53</span>${chips(nist, "chip-nist")}</div>` : ""}
      ${cis.length  ? `<div class="compliance-row"><span class="compliance-label">CIS v8</span>${chips(cis, "chip-cis")}</div>` : ""}
      ${iso.length  ? `<div class="compliance-row"><span class="compliance-label">ISO 27001</span>${chips(iso, "chip-iso")}</div>` : ""}
    `;
  } catch { panel.style.display = "none"; }
}

// ── Exposure / vendor advisory panel (detail overlay) ────────────────────────

async function _loadExposurePanel(row) {
  const panel   = document.getElementById("exposure-panel");
  const content = document.getElementById("exposure-content");
  panel.style.display = "";
  try {
    content.innerHTML = '<span class="muted">Click "Check Advisories" to fetch.</span>';
  } catch { panel.style.display = "none"; }
}

document.getElementById("btn-detail-check-exposure").addEventListener("click", async () => {
  if (!_detailRow) return;
  const msg = document.getElementById("exposure-msg");
  const btn = document.getElementById("btn-detail-check-exposure");
  btn.disabled = true;
  msg.textContent = "Fetching…"; msg.className = "form-msg";
  try {
    const r = await fetch(`${API}/api/exposure/${encodeURIComponent(_detailRow.cve_id)}`, { method: "POST", headers: { "X-CSRF-Token": _csrfToken() } });
    const d = await r.json();
    const content = document.getElementById("exposure-content");
    const advisories = (d.advisories || []);
    if (!advisories.length) {
      content.innerHTML = '<span class="muted">No vendor advisories found.</span>';
      msg.textContent = "No advisories."; msg.className = "form-msg";
    } else {
      content.innerHTML = advisories.map(a => `
        <div class="advisory-card">
          <div style="display:flex;align-items:center;gap:.5rem">
            <strong>${escHtml(a.source)}</strong>
            ${a.severity ? `<span class="badge" style="background:var(--medium);font-size:10px">${escHtml(a.severity)}</span>` : ""}
            ${a.url ? `<a href="${escHtml(a.url)}" target="_blank" rel="noopener" style="font-size:11px;color:#60a5fa">Advisory ↗</a>` : ""}
          </div>
          ${(a.packages||[]).length ? `<div class="muted" style="font-size:11px;margin-top:.2rem">Packages: ${escHtml(a.packages.slice(0,5).join(", "))}</div>` : ""}
        </div>
      `).join("");
      msg.textContent = `${advisories.length} advisory source(s) found.`; msg.className = "form-msg ok";
    }
  } catch { msg.textContent = "Fetch failed"; msg.className = "form-msg err"; }
  btn.disabled = false;
  setTimeout(() => { msg.textContent = ""; }, 4000);
});

// ── Comments (detail overlay) ─────────────────────────────────────────────────

async function _loadComments(row) {
  const list = document.getElementById("comments-list");
  list.innerHTML = '<span class="muted" style="font-size:12px">Loading…</span>';
  try {
    const r = await fetch(`${API}/api/comments/${encodeURIComponent(row.cve_id)}`);
    const comments = await r.json();
    if (!comments.length) {
      list.innerHTML = '<span class="muted" style="font-size:12px">No comments yet.</span>';
      return;
    }
    list.innerHTML = comments.map(c => `
      <div class="comment-item">
        <div class="comment-meta">
          <strong>${escHtml(c.author || "anon")}</strong>
          <span class="muted">${escHtml((c.created_at||"").slice(0,16))}</span>
        </div>
        <div class="comment-body">${escHtml(c.body)}</div>
      </div>
    `).join("");
  } catch { list.innerHTML = '<span class="muted">Failed to load.</span>'; }
}

document.getElementById("btn-comment-add").addEventListener("click", async () => {
  if (!_detailRow) return;
  const input = document.getElementById("comment-input");
  const body  = input.value.trim();
  if (!body) return;
  try {
    const r = await fetch(`${API}/api/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify({ cve_id: _detailRow.cve_id, body }),
    });
    const j = await r.json();
    if (j.ok) {
      input.value = "";
      await _loadComments(_detailRow);
    }
  } catch {}
});

document.getElementById("comment-input").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); document.getElementById("btn-comment-add").click(); }
});

// ── Extend openDetail to load new panels ─────────────────────────────────────

const _origOpenDetail2 = openDetail;
openDetail = async function(row) {
  await _origOpenDetail2(row);
  await Promise.allSettled([
    _loadThreatIntel(row),
    _loadRiskScore(row),
    _loadCompliance(row),
    _loadExposurePanel(row),
    _loadComments(row),
  ]);
};

// ── MTTR panel ────────────────────────────────────────────────────────────────

async function loadMttr() {
  try {
    const r = await fetch(`${API}/api/metrics/mttr`);
    const d = await r.json();
    document.getElementById("mttr-days").textContent        = d.mttr_days != null ? d.mttr_days : "—";
    document.getElementById("mttr-remediated").textContent  = d.remediated ?? "—";
    document.getElementById("mttr-open").textContent        = d.open ?? "—";
    document.getElementById("mttr-overdue").textContent     = d.overdue ?? "—";

    const statesEl = document.getElementById("mttr-states");
    statesEl.innerHTML = "";
    Object.entries(d.state_counts || {}).forEach(([state, cnt]) => {
      statesEl.insertAdjacentHTML("beforeend",
        `<span class="triage-badge triage-${escHtml(state)}" style="padding:.3rem .7rem;font-size:12px">${_triageLabel(state)}: ${cnt}</span>`);
    });

    // SLA health bar
    const open    = d.open    ?? 0;
    const overdue = d.overdue ?? 0;
    const barWrap = document.getElementById("sla-bar-wrap");
    if (open > 0) {
      const pct       = Math.round(((open - overdue) / open) * 100);
      const fill      = document.getElementById("sla-bar-fill");
      const label     = document.getElementById("sla-bar-label");
      fill.style.width      = `${pct}%`;
      fill.style.background = pct >= 80 ? "var(--success, #22c55e)" : pct >= 50 ? "var(--warning, #f59e0b)" : "var(--critical)";
      label.textContent     = overdue > 0 ? `${overdue} overdue / ${open} open` : `${open} open — all on time`;
      barWrap.style.display = "";
    } else {
      barWrap.style.display = "none";
    }
  } catch (e) { console.error("loadMttr:", e); }
}

document.getElementById("btn-refresh-mttr").addEventListener("click", loadMttr);

// ── HTML Report download ──────────────────────────────────────────────────────

document.getElementById("btn-report-html").addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = `${API}/api/report/html`;
  a.download = "";
  a.click();
});

// ── Threat Intel section ──────────────────────────────────────────────────────

async function loadThreatSection() {
  try {
    const r = await fetch(`${API}/api/threat`);
    const rows = await r.json();
    const tbody   = document.getElementById("threat-tbody");
    const emptyEl = document.getElementById("threat-empty");
    tbody.innerHTML = "";
    if (!rows.length) { emptyEl.style.display = ""; return; }
    emptyEl.style.display = "none";
    rows.forEach(row => {
      const badge = row.in_wild
        ? `<span class="badge badge-CRITICAL">In Wild</span>`
        : `<span class="muted">No</span>`;
      const mf = (row.malware_families || []).slice(0,3).map(m => `<span class="threat-chip threat-malware">${escHtml(m)}</span>`).join("");
      const cp = (row.campaigns || []).slice(0,3).map(c => `<span class="threat-chip threat-campaign">${escHtml(c)}</span>`).join("");
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td><code>${escHtml(row.cve_id)}</code></td>
          <td>${badge}</td>
          <td>${mf || '<span class="muted">—</span>'}</td>
          <td>${cp || '<span class="muted">—</span>'}</td>
          <td><small>${escHtml(row.source||"—")}</small></td>
          <td><small>${escHtml((row.updated_at||"").slice(0,16))}</small></td>
        </tr>
      `);
    });
  } catch (e) { console.error("loadThreatSection:", e); }
}

document.getElementById("btn-threat-refresh").addEventListener("click", loadThreatSection);

// ── Routing rules section ─────────────────────────────────────────────────────

let _editingRule = null;

function _openRoutingEditor(rule = null) {
  _editingRule = rule || null;
  document.getElementById("routing-editor-title").textContent = rule ? `Edit — ${escHtml(rule.name)}` : "New Rule";
  document.getElementById("routing-edit-id").value    = rule?.id || "";
  document.getElementById("routing-name").value       = rule?.name || "";
  document.getElementById("routing-severity").value   = rule?.min_severity || "CRITICAL";
  document.getElementById("routing-channel").value    = rule?.channel || "pagerduty";
  document.getElementById("routing-destination").value = rule?.destination || "";
  document.getElementById("routing-tag").value        = rule?.tag_filter || "";
  document.getElementById("btn-routing-delete").style.display = rule ? "" : "none";
  document.getElementById("routing-msg").textContent  = "";
  document.getElementById("routing-editor").classList.add("visible");
}

function _closeRoutingEditor() {
  _editingRule = null;
  document.getElementById("routing-editor").classList.remove("visible");
}

async function loadRoutingRules() {
  try {
    const r    = await fetch(`${API}/api/routing`);
    const rows = await r.json();
    const tbody   = document.getElementById("routing-tbody");
    const emptyEl = document.getElementById("routing-empty");
    tbody.innerHTML = "";
    if (!rows.length) { emptyEl.style.display = ""; return; }
    emptyEl.style.display = "none";
    rows.forEach(rule => {
      const tr = document.createElement("tr");
      tr.className = "clickable";
      tr.innerHTML = `
        <td><strong>${escHtml(rule.name)}</strong></td>
        <td>${sevBadge(rule.min_severity)}</td>
        <td><span class="badge" style="background:var(--accent)">${escHtml(rule.channel)}</span></td>
        <td><small class="muted">${escHtml(truncate(rule.destination||"",40))}</small></td>
        <td><small>${escHtml(rule.tag_filter||"—")}</small></td>
        <td><button class="btn-sm">Edit</button></td>
      `;
      tr.querySelector("button").addEventListener("click", e => { e.stopPropagation(); _openRoutingEditor(rule); });
      tr.addEventListener("click", () => _openRoutingEditor(rule));
      tbody.appendChild(tr);
    });
  } catch (e) { console.error("loadRoutingRules:", e); }
}

document.getElementById("btn-routing-new").addEventListener("click", () => _openRoutingEditor());
document.getElementById("btn-routing-cancel").addEventListener("click", _closeRoutingEditor);

document.getElementById("btn-routing-save").addEventListener("click", async () => {
  const msg  = document.getElementById("routing-msg");
  const name = document.getElementById("routing-name").value.trim();
  const dest = document.getElementById("routing-destination").value.trim();
  if (!name || !dest) { msg.textContent = "Name and destination are required."; msg.className = "form-msg err"; return; }
  const body = {
    name,
    min_severity: document.getElementById("routing-severity").value,
    channel:      document.getElementById("routing-channel").value,
    destination:  dest,
    tag_filter:   document.getElementById("routing-tag").value.trim(),
  };
  const editId = document.getElementById("routing-edit-id").value;
  if (editId) body.id = parseInt(editId, 10);
  try {
    const r = await fetch(`${API}/api/routing`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": _csrfToken() },
      body: JSON.stringify(body),
    });
    const j = await r.json();
    if (j.ok) { msg.textContent = "Saved!"; msg.className = "form-msg ok"; loadRoutingRules(); setTimeout(_closeRoutingEditor, 600); }
    else { msg.textContent = j.error || "Failed"; msg.className = "form-msg err"; }
  } catch { msg.textContent = "Request failed"; msg.className = "form-msg err"; }
});

document.getElementById("btn-routing-delete").addEventListener("click", async () => {
  if (!_editingRule) return;
  if (!confirm(`Delete rule "${_editingRule.name}"?`)) return;
  await fetch(`${API}/api/routing/${_editingRule.id}`, { method: "DELETE", headers: { "X-CSRF-Token": _csrfToken() } });
  loadRoutingRules();
  _closeRoutingEditor();
});

// ── Audit log section ─────────────────────────────────────────────────────────

async function loadAuditLog() {
  try {
    const r = await fetch(`${API}/api/audit?limit=200`);
    const rows = await r.json();
    const tbody = document.getElementById("audit-tbody");
    tbody.innerHTML = "";
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted" style="padding:1rem">No audit entries yet.</td></tr>`;
      return;
    }
    rows.forEach(row => {
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td><small>${escHtml((row.ts||"").slice(0,16))}</small></td>
          <td>${escHtml(row.actor||"—")}</td>
          <td><code style="font-size:11px">${escHtml(row.action||"")}</code></td>
          <td>${row.target_id ? `<code>${escHtml(row.target_id)}</code>` : "—"}</td>
          <td><small class="muted">${escHtml(truncate(row.detail||"",80))}</small></td>
        </tr>
      `);
    });
  } catch (e) { console.error("loadAuditLog:", e); }
}

document.getElementById("btn-audit-refresh").addEventListener("click", loadAuditLog);


// ── Initial load ──────────────────────────────────────────────────────────────

loadDashboard();
loadTopCves();
loadTrend();
loadEpssChart();
loadSeverityChart();
loadKwPerf();
loadScheduleInfo();
loadScanHealth();
loadMttr();
renderSavedSearches();
