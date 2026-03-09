"""Self-contained live dashboard HTML page (no CDN, no external deps)."""


def render_dashboard() -> str:
    """Return a complete HTML page for the live web dashboard."""
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Snaffler Live</title>
<style>
  * { box-sizing: border-box; }
  body { background: #1e1e1e; color: #d4d4d4; font-family: 'Cascadia Code', 'Fira Code', monospace; margin: 0; padding: 20px; }
  h1 { color: #e0e0e0; margin-bottom: 4px; display: inline-block; }
  h2 { color: #e0e0e0; margin: 20px 0 8px; }
  .header { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
  .elapsed { color: #888; font-size: 0.95em; font-variant-numeric: tabular-nums; }
  .phase-badge { display: inline-flex; align-items: center; gap: 6px; background: #2d2d2d; border-radius: 6px; padding: 4px 12px; font-size: 0.85em; color: #ccc; }
  .phase-dot { width: 8px; height: 8px; border-radius: 50%; background: #27ae60; }
  .phase-dot.active { animation: pulse 1.2s ease-in-out infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
  .card { background: #2d2d2d; border-radius: 8px; padding: 16px 24px; min-width: 140px; text-align: center; }
  .card-value { font-size: 1.4em; font-weight: bold; color: #fff; transition: all 0.3s; }
  .card-label { color: #888; font-size: 0.85em; margin-top: 4px; }
  .toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; }
  .severities { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; }
  .severity { display: flex; align-items: center; gap: 6px; font-size: 1em; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; color: #fff; font-weight: bold; font-size: 0.85em; }
  .badge[data-triage] { cursor: pointer; user-select: none; transition: opacity 0.15s; }
  .badge[data-triage].active { outline: 2px solid #fff; outline-offset: 1px; }
  .badge[data-triage].dimmed { opacity: 0.35; }
  #clear-filter { background: #333; color: #aaa; border: 1px solid #444; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-family: inherit; font-size: 0.85em; }
  #clear-filter:hover { background: #444; color: #fff; }
  #rule-filter { padding: 8px 12px; background: #2d2d2d; color: #d4d4d4; border: 1px solid #444; border-radius: 6px; font-family: inherit; font-size: 0.9em; outline: none; max-width: 260px; }
  #rule-filter:focus { border-color: #888; }
  #search { flex: 1; min-width: 200px; padding: 10px 14px; background: #2d2d2d; color: #d4d4d4; border: 1px solid #444; border-radius: 6px; font-family: inherit; font-size: 1em; outline: none; }
  #search:focus { border-color: #888; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; border-bottom: 2px solid #444; color: #aaa; font-size: 0.8em; text-transform: uppercase; cursor: pointer; user-select: none; white-space: nowrap; }
  th:hover { color: #fff; }
  th.sort-asc::after { content: ' \2191'; color: #fff; }
  th.sort-desc::after { content: ' \2193'; color: #fff; }
  td { padding: 8px 12px; border-bottom: 1px solid #2a2a2a; vertical-align: top; }
  tbody tr { cursor: pointer; transition: filter 0.1s; }
  tbody tr:hover { filter: brightness(1.3); }
  tr[data-triage="Black"] { background: #271515; }
  tr[data-triage="Red"] { background: #221212; }
  tr[data-triage="Yellow"] { background: #201e0d; }
  tr[data-triage="Green"] { background: #131d13; }
  .path { word-break: break-all; max-width: 320px; }
  .match { display: block; margin-top: 4px; font-size: 0.8em; color: #ffd700; background: #1e1900; border-left: 2px solid #ffd700; padding: 2px 6px; word-break: break-all; }
  .context { font-size: 0.82em; color: #999; max-width: 280px; word-break: break-all; }
  .footer { margin-top: 30px; color: #555; font-size: 0.8em; border-top: 1px solid #333; padding-top: 10px; }
  /* Modal */
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.75); display: flex; align-items: center; justify-content: center; z-index: 1000; padding: 20px; }
  .overlay.hidden { display: none; }
  .modal { background: #252525; border-radius: 10px; padding: 28px 32px; width: 100%; max-width: 820px; max-height: 88vh; overflow-y: auto; position: relative; border: 1px solid #3a3a3a; }
  .modal-header { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
  .modal-rule { flex: 1; font-size: 1em; font-weight: bold; color: #e0e0e0; word-break: break-all; }
  .modal-close { background: none; border: none; color: #666; font-size: 1.5em; cursor: pointer; line-height: 1; padding: 0; flex-shrink: 0; }
  .modal-close:hover { color: #fff; }
  .modal-field { margin-bottom: 14px; }
  .modal-field label { color: #666; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 4px; }
  .modal-path { word-break: break-all; display: flex; gap: 10px; align-items: flex-start; }
  .modal-path span { flex: 1; }
  .copy-btn { background: #333; border: 1px solid #555; color: #aaa; border-radius: 4px; padding: 2px 8px; font-size: 0.75em; cursor: pointer; flex-shrink: 0; font-family: inherit; }
  .copy-btn:hover { background: #444; color: #fff; }
  .modal-meta { display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 14px; }
  .modal-match { background: #1a1500; border-left: 3px solid #ffd700; padding: 10px 14px; color: #ffd700; white-space: pre-wrap; word-break: break-all; font-size: 0.88em; border-radius: 0 4px 4px 0; }
  .modal-context { background: #1a1a1a; border-left: 3px solid #444; padding: 10px 14px; color: #aaa; white-space: pre-wrap; word-break: break-all; font-size: 0.85em; border-radius: 0 4px 4px 0; }
  .new-row { animation: fadeIn 0.4s ease-out; }
  @keyframes fadeIn { from { opacity: 0; background: #333; } to { opacity: 1; } }
</style>
</head>
<body>
<div class="header">
  <h1>Snaffler Live</h1>
  <span class="elapsed" id="elapsed">00:00:00</span>
  <div class="phase-badge">
    <span class="phase-dot active" id="phase-dot"></span>
    <span id="phase-text">Initializing</span>
  </div>
</div>

<div class="cards">
  <div class="card"><div class="card-value" id="card-dns">0</div><div class="card-label">DNS Resolved</div></div>
  <div class="card"><div class="card-value" id="card-computers">0 / 0</div><div class="card-label">Computers</div></div>
  <div class="card"><div class="card-value" id="card-shares">0 / 0</div><div class="card-label">Shares</div></div>
  <div class="card"><div class="card-value" id="card-files">0 / 0</div><div class="card-label">Files</div></div>
</div>

<div class="toolbar">
  <div class="severities">
    <div class="severity"><span class="badge" data-triage="Black" style="background:#888">Black</span> <span id="sev-black">0</span></div>
    <div class="severity"><span class="badge" data-triage="Red" style="background:#e74c3c">Red</span> <span id="sev-red">0</span></div>
    <div class="severity"><span class="badge" data-triage="Yellow" style="background:#f1c40f">Yellow</span> <span id="sev-yellow">0</span></div>
    <div class="severity"><span class="badge" data-triage="Green" style="background:#27ae60">Green</span> <span id="sev-green">0</span></div>
  </div>
  <select id="rule-filter"><option value="">All Rules</option></select>
  <button id="clear-filter">Show All</button>
  <input id="search" type="text" placeholder="Filter findings (searches match &amp; context)..." />
</div>

<h2>Findings (<span id="findings-visible">0</span> / <span id="findings-count">0</span>)</h2>
<table id="tbl">
<thead><tr>
  <th data-col="0">Triage</th>
  <th data-col="1">Rule</th>
  <th data-col="2">Path</th>
  <th data-col="3">Size</th>
  <th data-col="4">Modified</th>
  <th data-col="5">Context</th>
</tr></thead>
<tbody></tbody>
</table>

<div class="footer">snaffler-ng live dashboard</div>

<!-- Modal -->
<div class="overlay hidden" id="overlay">
  <div class="modal">
    <div class="modal-header">
      <span id="m-badge"></span>
      <span class="modal-rule" id="m-rule"></span>
      <button class="modal-close" id="modal-close">&#x2715;</button>
    </div>
    <div class="modal-field">
      <label>Path</label>
      <div class="modal-path">
        <span id="m-path"></span>
        <button class="copy-btn" id="copy-path">Copy</button>
      </div>
    </div>
    <div class="modal-meta">
      <div class="modal-field"><label>Size</label><span id="m-size"></span></div>
      <div class="modal-field"><label>Modified</label><span id="m-mtime"></span></div>
    </div>
    <div class="modal-field" id="m-match-wrap">
      <label>Match</label>
      <div class="modal-match" id="m-match"></div>
    </div>
    <div class="modal-field">
      <label>Context</label>
      <div class="modal-context" id="m-context"></div>
    </div>
  </div>
</div>

<script>
(function() {
  "use strict";

  var TRIAGE_ORDER = {"Black":0,"Red":1,"Yellow":2,"Green":3};
  var TRIAGE_COLOR = {"Black":"#888","Red":"#e74c3c","Yellow":"#f1c40f","Green":"#27ae60"};

  var activeTriage = null;
  var activeRule = "";
  var lastRowid = 0;
  var findingsData = [];  // stores {match, context, rule} for modal + filter
  var seenIds = {};       // finding_id → true (dedup on resume)
  var knownRules = {};    // rule_name → true (for dropdown dedup)
  var pollActive = true;
  var stopScheduled = false;
  var serverElapsed = 0;
  var localSyncTime = Date.now();

  // ── Elapsed timer ──────────────────────────────────────────────
  var elapsedEl = document.getElementById("elapsed");
  var timerIval = setInterval(function() {
    var now = Date.now();
    var totalSec = serverElapsed + Math.floor((now - localSyncTime) / 1000);
    if (totalSec < 0) totalSec = 0;
    var h = Math.floor(totalSec / 3600);
    var m = Math.floor((totalSec % 3600) / 60);
    var s = totalSec % 60;
    elapsedEl.textContent =
      (h < 10 ? "0" : "") + h + ":" +
      (m < 10 ? "0" : "") + m + ":" +
      (s < 10 ? "0" : "") + s;
  }, 1000);

  // ── Phase mapping ─────────────────────────────────────────────
  var PHASE_LABELS = {
    "idle": "Initializing",
    "dns": "DNS Resolution",
    "shares": "Share Discovery",
    "walking": "Tree Walking",
    "scanning": "File Scanning",
    "complete": "Complete"
  };

  // ── Helpers ───────────────────────────────────────────────────
  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  function makeBadge(triage) {
    var color = TRIAGE_COLOR[triage] || "#888";
    return '<span class="badge" style="background:' + color + '">' + esc(triage) + '</span>';
  }

  // ── Severity filter ───────────────────────────────────────────
  document.querySelectorAll(".badge[data-triage]").forEach(function(badge) {
    badge.addEventListener("click", function() {
      var t = this.getAttribute("data-triage");
      activeTriage = (activeTriage === t) ? null : t;
      syncBadges();
      applyFilter();
    });
  });

  document.getElementById("clear-filter").addEventListener("click", function() {
    activeTriage = null;
    activeRule = "";
    document.getElementById("rule-filter").value = "";
    document.getElementById("search").value = "";
    syncBadges();
    applyFilter();
  });

  document.getElementById("rule-filter").addEventListener("change", function() {
    activeRule = this.value;
    applyFilter();
  });

  function syncBadges() {
    document.querySelectorAll(".badge[data-triage]").forEach(function(b) {
      var t = b.getAttribute("data-triage");
      b.classList.toggle("active", activeTriage === t);
      b.classList.toggle("dimmed", activeTriage !== null && activeTriage !== t);
    });
  }

  // ── Search + filter ───────────────────────────────────────────
  document.getElementById("search").addEventListener("input", applyFilter);

  function applyFilter() {
    var term = document.getElementById("search").value.toLowerCase();
    var visible = 0;
    document.querySelectorAll("#tbl tbody tr").forEach(function(row) {
      var triageOk = !activeTriage || row.getAttribute("data-triage") === activeTriage;
      var ruleOk = !activeRule || row.getAttribute("data-rule") === activeRule;
      var textOk = true;
      if (term) {
        // Search visible text + full match/context from data array
        var idx = parseInt(row.getAttribute("data-idx"));
        var data = findingsData[idx] || {};
        var haystack = row.textContent.toLowerCase()
          + "\n" + (data.match || "").toLowerCase()
          + "\n" + (data.context || "").toLowerCase();
        textOk = haystack.indexOf(term) !== -1;
      }
      var show = triageOk && ruleOk && textOk;
      row.style.display = show ? "" : "none";
      if (show) visible++;
    });
    document.getElementById("findings-visible").textContent = visible.toLocaleString();
  }

  // ── Sortable columns ─────────────────────────────────────────
  var sortCol = -1, sortAsc = true;

  function sortTable() {
    if (sortCol === -1) return;
    var tbody = document.querySelector("#tbl tbody");
    var rows = Array.from(tbody.querySelectorAll("tr"));
    rows.sort(function(a, b) {
      if (sortCol === 0) {
        var at = a.getAttribute("data-triage");
        var bt = b.getAttribute("data-triage");
        var ao = at in TRIAGE_ORDER ? TRIAGE_ORDER[at] : 99;
        var bo = bt in TRIAGE_ORDER ? TRIAGE_ORDER[bt] : 99;
        return sortAsc ? (ao - bo) : (bo - ao);
      }
      var av = a.cells[sortCol] ? a.cells[sortCol].textContent.trim() : "";
      var bv = b.cells[sortCol] ? b.cells[sortCol].textContent.trim() : "";
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(function(r) { tbody.appendChild(r); });
  }

  document.querySelectorAll("th[data-col]").forEach(function(th) {
    th.addEventListener("click", function() {
      var col = parseInt(this.getAttribute("data-col"));
      sortAsc = (sortCol === col) ? !sortAsc : true;
      sortCol = col;
      document.querySelectorAll("th").forEach(function(h) { h.classList.remove("sort-asc", "sort-desc"); });
      th.classList.add(sortAsc ? "sort-asc" : "sort-desc");
      sortTable();
    });
  });

  // ── Modal ─────────────────────────────────────────────────────
  var overlay = document.getElementById("overlay");

  function openModal(row) {
    var idx = parseInt(row.getAttribute("data-idx"));
    var data = findingsData[idx] || {};
    var triage = row.getAttribute("data-triage");
    var color = TRIAGE_COLOR[triage] || "#888";
    document.getElementById("m-badge").innerHTML =
      '<span class="badge" style="background:' + color + '">' + esc(triage) + '</span>';
    document.getElementById("m-rule").textContent = row.getAttribute("data-rule");
    document.getElementById("m-path").textContent = row.getAttribute("data-path");
    document.getElementById("m-size").textContent = row.getAttribute("data-size");
    document.getElementById("m-mtime").textContent = row.getAttribute("data-mtime");
    var matchWrap = document.getElementById("m-match-wrap");
    if (data.match) {
      document.getElementById("m-match").textContent = data.match;
      matchWrap.style.display = "";
    } else {
      matchWrap.style.display = "none";
    }
    document.getElementById("m-context").textContent = data.context || "";
    overlay.classList.remove("hidden");
  }

  document.getElementById("modal-close").addEventListener("click", function() {
    overlay.classList.add("hidden");
  });
  overlay.addEventListener("click", function(e) {
    if (e.target === overlay) overlay.classList.add("hidden");
  });
  document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") overlay.classList.add("hidden");
  });
  document.getElementById("copy-path").addEventListener("click", function(e) {
    e.stopPropagation();
    navigator.clipboard.writeText(document.getElementById("m-path").textContent);
    var btn = this;
    btn.textContent = "Copied!";
    setTimeout(function() { btn.textContent = "Copy"; }, 1500);
  });

  // ── Add finding row ───────────────────────────────────────────
  function addFindingRow(f) {
    var idx = findingsData.length;
    findingsData.push({match: f.match_text || "", context: f.context || "", rule: f.rule_name || ""});

    // Populate rule dropdown
    if (f.rule_name && !knownRules[f.rule_name]) {
      knownRules[f.rule_name] = true;
      var opt = document.createElement("option");
      opt.value = f.rule_name;
      opt.textContent = f.rule_name;
      document.getElementById("rule-filter").appendChild(opt);
    }

    var tbody = document.querySelector("#tbl tbody");
    var tr = document.createElement("tr");
    tr.setAttribute("data-idx", idx);
    tr.setAttribute("data-triage", f.triage);
    tr.setAttribute("data-rule", f.rule_name);
    tr.setAttribute("data-path", f.file_path);
    tr.setAttribute("data-size", f.size_str || "");
    tr.setAttribute("data-mtime", f.mtime || "");
    tr.className = "new-row";

    var ctxDisplay = (f.context || "").substring(0, 200);
    if ((f.context || "").length > 200) ctxDisplay += "\u2026";
    var matchDisplay = (f.match_text || "").substring(0, 120);
    if ((f.match_text || "").length > 120) matchDisplay += "\u2026";

    var matchHtml = "";
    if (matchDisplay) {
      matchHtml = '<span class="match"></span>';
    }

    // Build cells using textContent for XSS safety, except badge which is controlled
    tr.innerHTML =
      "<td>" + makeBadge(f.triage) + "</td>" +
      "<td></td>" +
      '<td class="path"></td>' +
      "<td></td>" +
      "<td></td>" +
      '<td class="context"></td>';

    tr.cells[1].textContent = f.rule_name;
    tr.cells[2].textContent = f.file_path;
    tr.cells[3].textContent = f.size_str || "";
    tr.cells[4].textContent = f.mtime || "";

    // Context cell: set text safely
    var ctxCell = tr.cells[5];
    ctxCell.textContent = ctxDisplay;
    if (matchDisplay) {
      var matchSpan = document.createElement("span");
      matchSpan.className = "match";
      matchSpan.textContent = matchDisplay;
      ctxCell.appendChild(matchSpan);
    }

    tr.addEventListener("click", function() { openModal(this); });

    // Prepend (newest first)
    if (tbody.firstChild) {
      tbody.insertBefore(tr, tbody.firstChild);
    } else {
      tbody.appendChild(tr);
    }

    // Apply current filter
    var triageOk = !activeTriage || f.triage === activeTriage;
    var ruleOk = !activeRule || f.rule_name === activeRule;
    var term = document.getElementById("search").value.toLowerCase();
    var textOk = true;
    if (term) {
      var haystack = tr.textContent.toLowerCase()
        + "\n" + (f.match_text || "").toLowerCase()
        + "\n" + (f.context || "").toLowerCase();
      textOk = haystack.indexOf(term) !== -1;
    }
    if (!(triageOk && ruleOk && textOk)) {
      tr.style.display = "none";
    }
  }

  // ── Polling: progress ─────────────────────────────────────────
  function pollProgress() {
    if (!pollActive) return;
    fetch("/api/progress").then(function(r) { return r.json(); }).then(function(d) {
      // Elapsed
      serverElapsed = d.elapsed_seconds || 0;
      localSyncTime = Date.now();

      // Phase
      var phaseEl = document.getElementById("phase-text");
      var dotEl = document.getElementById("phase-dot");
      phaseEl.textContent = PHASE_LABELS[d.phase] || d.phase;
      if (d.phase === "complete") {
        dotEl.classList.remove("active");
        dotEl.style.background = "#888";
        if (!stopScheduled) {
          stopScheduled = true;
          // One final findings poll after BatchWriter flush window
          setTimeout(function() {
            fetchFindings();
            pollActive = false;
            clearInterval(timerIval);
            clearInterval(progressIval);
            clearInterval(findingsIval);
          }, 2000);
        }
      } else {
        dotEl.classList.add("active");
        dotEl.style.background = "#27ae60";
      }

      // Cards
      document.getElementById("card-dns").textContent = (d.dns_resolved || 0).toLocaleString();
      document.getElementById("card-computers").textContent =
        (d.computers_done || 0).toLocaleString() + " / " + (d.computers_total || 0).toLocaleString();
      document.getElementById("card-shares").textContent =
        (d.shares_walked || 0).toLocaleString() + " / " + (d.shares_total || d.shares_found || 0).toLocaleString();
      document.getElementById("card-files").textContent =
        (d.files_scanned || 0).toLocaleString() + " / " + (d.files_total || 0).toLocaleString();

      // Severity
      document.getElementById("sev-black").textContent = (d.severity_black || 0).toLocaleString();
      document.getElementById("sev-red").textContent = (d.severity_red || 0).toLocaleString();
      document.getElementById("sev-yellow").textContent = (d.severity_yellow || 0).toLocaleString();
      document.getElementById("sev-green").textContent = (d.severity_green || 0).toLocaleString();

      // Findings count (total from server)
      var total = (d.severity_black || 0) + (d.severity_red || 0) + (d.severity_yellow || 0) + (d.severity_green || 0);
      document.getElementById("findings-count").textContent = total.toLocaleString();
    }).catch(function() {});
  }

  // ── Polling: findings ─────────────────────────────────────────
  function fetchFindings() {
    var url = "/api/findings?since_rowid=" + lastRowid;
    fetch(url).then(function(r) { return r.json(); }).then(function(data) {
      if (data.findings && data.findings.length > 0) {
        // Add in reverse so newest ends up on top
        for (var i = data.findings.length - 1; i >= 0; i--) {
          var f = data.findings[i];
          if (seenIds[f.finding_id]) continue;
          seenIds[f.finding_id] = true;
          addFindingRow(f);
        }
        lastRowid = data.max_rowid || lastRowid;
        sortTable();
        applyFilter();
      }
    }).catch(function() {});
  }

  function pollFindings() {
    if (!pollActive) return;
    fetchFindings();
  }

  // ── Start polling ─────────────────────────────────────────────
  pollProgress();
  fetchFindings();

  var progressIval = setInterval(pollProgress, 2500);
  var findingsIval = setInterval(pollFindings, 2500);
})();
</script>
</body>
</html>"""
