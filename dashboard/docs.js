// CVE Emailer — docs page logic

// Health check
async function checkHealth() {
  const dot  = document.getElementById("health-dot");
  const text = document.getElementById("health-text");
  try {
    const r = await fetch("/health");
    const j = await r.json();
    if (j.status === "ok") {
      dot.className = "health-dot ok";
      text.textContent = "Connected";
    } else { throw new Error(); }
  } catch {
    dot.className = "health-dot err";
    text.textContent = "API unreachable";
  }
}
setInterval(checkHealth, 30_000);
checkHealth();

// TOC highlight on scroll
const tocLinks = document.querySelectorAll(".docs-toc a[href^='#']");
const headings = Array.from(document.querySelectorAll("h2[id], h3[id]"));

function updateToc() {
  const scrollY = window.scrollY + 80;
  let active = headings[0];
  for (const h of headings) {
    if (h.offsetTop <= scrollY) active = h;
  }
  tocLinks.forEach(a => a.classList.toggle("active", a.getAttribute("href") === `#${active?.id}`));
}

window.addEventListener("scroll", updateToc, { passive: true });
updateToc();

// Script view/hide toggle
const _scriptUrls = {
  "script-py":  "/scanners/scan_environment.py",
  "script-sh":  "/scanners/scan_environment.sh",
  "script-ps1": "/scanners/Scan-Environment.ps1",
};
const _scriptCache = {};

async function toggleScript(id, btn) {
  const pre  = document.getElementById(id);
  const code = document.getElementById(id + "-code");
  if (pre.style.display !== "none") {
    pre.style.display = "none";
    btn.textContent = "View script";
    return;
  }
  if (!_scriptCache[id]) {
    btn.textContent = "Loading…";
    try {
      const text = await (await fetch(_scriptUrls[id])).text();
      _scriptCache[id] = text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    } catch { btn.textContent = "View script"; return; }
  }
  code.innerHTML    = _scriptCache[id];
  pre.style.display = "";
  btn.textContent   = "Hide script";
}

document.getElementById("btn-view-script-py").addEventListener("click", function() { toggleScript("script-py", this); });
document.getElementById("btn-view-script-sh").addEventListener("click", function() { toggleScript("script-sh", this); });
document.getElementById("btn-view-script-ps1").addEventListener("click", function() { toggleScript("script-ps1", this); });
