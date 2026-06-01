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
  e.preventDefault();
  const sec = l.dataset.section;
  showSection(sec);
  if (sec === "overview")  loadDashboard();
  if (sec === "history")   loadHistory();
  if (sec === "profiles")  loadProfiles();
  if (sec === "browse")    loadBrowseTables();
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

document.getElementById("btn-refresh-dashboard").addEventListener("click", loadDashboard);

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
    renderBrowseResults();
  } catch (e) {
    console.error("doBrowseSearch:", e);
  }
}

function renderBrowseResults() {
  const tbody = document.getElementById("browse-tbody");
  tbody.innerHTML = "";
  _browseRows.forEach((row, idx) => {
    tbody.insertAdjacentHTML("beforeend", `
      <tr class="clickable" data-idx="${idx}">
        <td><code>${escHtml(row.cve_id)}</code></td>
        <td>${sevBadge(row.severity)}</td>
        <td class="num">${scoreStr(row.cvss_score)}</td>
        <td class="num">${epssStr(row.epss_score)}</td>
        <td>${kevBadge(row.kev)}</td>
        <td>${escHtml(row.keyword || "")}</td>
        <td>${escHtml((row.publish_date || "").slice(0, 10))}</td>
        <td>${escHtml(truncate(row.description, 90))}</td>
      </tr>
    `);
  });
  document.getElementById("browse-tbody").querySelectorAll("tr[data-idx]").forEach(tr => {
    tr.addEventListener("click", () => openDetail(_browseRows[+tr.dataset.idx]));
  });
  document.getElementById("browse-status").textContent = `${_browseRows.length} result(s) — click a row for detail`;
}

document.getElementById("btn-browse-search").addEventListener("click", doBrowseSearch);
document.getElementById("br-search").addEventListener("keydown", e => { if (e.key === "Enter") doBrowseSearch(); });

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

function openDetail(row) {
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

// ── Scan History ──────────────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const r = await fetch(`${API}/api/history?limit=100`);
    const rows = await r.json();
    const tbody = document.getElementById("history-tbody");
    tbody.innerHTML = "";
    rows.forEach(row => {
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td>${escHtml((row.started_at || "").slice(0, 16))}</td>
          <td>${escHtml((row.finished_at || "").slice(0, 16))}</td>
          <td>${escHtml(truncate(row.keywords || "", 40))}</td>
          <td class="num">${row.new_cves ?? 0}</td>
          <td class="num">${row.updated_cves ?? 0}</td>
          <td>${row.emailed ? "✓" : ""}</td>
          <td><small style="color:${row.error ? "var(--critical)" : "inherit"}">${escHtml(truncate(row.error || "", 40))}</small></td>
        </tr>
      `);
    });
  } catch (e) {
    console.error("loadHistory:", e);
  }
}

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

// ── Initial load ──────────────────────────────────────────────────────────────

loadDashboard();
