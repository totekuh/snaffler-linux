"""snaffler results — display stats and findings from a scan database."""

import html
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
import typer

from snaffler.utils.logger import Colors, format_size

results_app = typer.Typer(
    help="Display stats and findings from a scan database",
    add_completion=False,
)

TRIAGE_ORDER = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}
TRIAGE_COLORS = {
    "Black": Colors.BLACK + Colors.BOLD,
    "Red": Colors.RED + Colors.BOLD,
    "Yellow": Colors.YELLOW + Colors.BOLD,
    "Green": Colors.GREEN,
}


def _open_db(path: Path) -> sqlite3.Connection:
    if not path.exists():
        typer.echo(f"Error: database not found: {path}", err=True)
        raise typer.Exit(code=1)
    try:
        # Open read-write (default) so SQLite can recover/read WAL data.
        # The scanner uses WAL journal mode; after Ctrl+C the committed
        # findings may still be in the -wal file.  A ?mode=ro connection
        # cannot create the -shm file needed to read the WAL, so it would
        # silently miss those findings.
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError as exc:
        typer.echo(f"Error: cannot open database: {exc}", err=True)
        raise typer.Exit(code=1)


def _query_stats(conn: sqlite3.Connection) -> dict:
    def _count(table, col=None, val=None):
        if col:
            total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
            done = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {col} = ?", (val,)  # noqa: S608
            ).fetchone()[0]
            return {"total": total, "done": done}
        return {"total": conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]}  # noqa: S608

    stats = {}

    # Computers
    comp = _count("target_computer", "done", 1)
    resolved = conn.execute(
        "SELECT COUNT(*) FROM target_computer WHERE ip IS NOT NULL"
    ).fetchone()[0]
    comp["resolved"] = resolved
    stats["computers"] = comp

    # Shares
    stats["shares"] = _count("target_share", "done", 1)

    # Directories
    dir_stats = _count("target_dir", "walked", 1)
    stats["directories"] = {"total": dir_stats["total"], "walked": dir_stats["done"]}

    # Files
    file_stats = _count("target_file", "checked", 1)
    stats["files"] = {"total": file_stats["total"], "checked": file_stats["done"]}

    # Findings by triage
    rows = conn.execute(
        "SELECT triage, COUNT(*) as cnt FROM finding GROUP BY triage"
    ).fetchall()
    triage_counts = {row["triage"]: row["cnt"] for row in rows}
    finding_total = sum(triage_counts.values())
    stats["findings"] = {
        "total": finding_total,
        "black": triage_counts.get("Black", 0),
        "red": triage_counts.get("Red", 0),
        "yellow": triage_counts.get("Yellow", 0),
        "green": triage_counts.get("Green", 0),
    }

    return stats


def _query_findings(conn: sqlite3.Connection, min_interest: int) -> list:
    # Map min_interest (0=Green+, 1=Yellow+, 2=Red+, 3=Black only) to triage names
    threshold = 3 - min_interest  # Green=0→3, Yellow=1→2, Red=2→1, Black=3→0
    allowed = [name for name, order in TRIAGE_ORDER.items() if order <= threshold]

    if not allowed:
        return []

    placeholders = ",".join("?" for _ in allowed)
    rows = conn.execute(
        f"SELECT finding_id, file_path, triage, rule_name, "  # noqa: S608
        f"match_text, context, size, mtime, found_at "
        f"FROM finding WHERE triage IN ({placeholders}) "
        f"ORDER BY found_at",
        allowed,
    ).fetchall()

    findings = [dict(row) for row in rows]
    findings.sort(key=lambda f: TRIAGE_ORDER.get(f["triage"], 99))
    return findings


def _render_plain(stats: dict, findings: list, use_color: bool):
    lines = []

    lines.append(f"{'── Stats ':─<50}")
    c = stats["computers"]
    lines.append(
        f"Computers:   {c['total']:,} discovered, {c['resolved']:,} resolved, {c['done']:,} done"
    )
    s = stats["shares"]
    lines.append(f"Shares:      {s['total']:,} discovered, {s['done']:,} done")
    d = stats["directories"]
    lines.append(f"Directories: {d['total']:,} discovered, {d['walked']:,} walked")
    f = stats["files"]
    lines.append(f"Files:       {f['total']:,} discovered, {f['checked']:,} checked")

    lines.append("")
    fc = stats["findings"]
    lines.append(f"{'── Findings (' + str(fc['total']) + ') ':─<50}")

    if use_color:
        severity_parts = [
            f"{TRIAGE_COLORS['Black']}Black: {fc['black']}{Colors.RESET}",
            f"{TRIAGE_COLORS['Red']}Red: {fc['red']}{Colors.RESET}",
            f"{TRIAGE_COLORS['Yellow']}Yellow: {fc['yellow']}{Colors.RESET}",
            f"{TRIAGE_COLORS['Green']}Green: {fc['green']}{Colors.RESET}",
        ]
    else:
        severity_parts = [
            f"Black: {fc['black']}",
            f"Red: {fc['red']}",
            f"Yellow: {fc['yellow']}",
            f"Green: {fc['green']}",
        ]
    lines.append(" " + " | ".join(severity_parts))
    lines.append("")

    for finding in findings:
        triage = finding["triage"]
        rule = finding["rule_name"]
        path = finding["file_path"]
        size = finding["size"]

        size_str = f"[{format_size(size)}]" if size is not None else ""

        if use_color:
            color = TRIAGE_COLORS.get(triage, "")
            line = f"{color}[{triage}]{Colors.RESET} [{rule}] {size_str} {Colors.BOLD}{path}{Colors.RESET}"
        else:
            line = f"[{triage}] [{rule}] {size_str} {path}"

        lines.append(line)

        ctx = finding.get("context")
        if ctx:
            preview = ctx[:200] + ("..." if len(ctx) > 200 else "")
            lines.append(f"  Context: {preview}")

    typer.echo("\n".join(lines))


def _render_json(stats: dict, findings: list):
    output = {"stats": stats, "findings": findings}
    typer.echo(json.dumps(output, indent=2, default=str))


TRIAGE_HTML_COLORS = {
    "Black": "#888",
    "Red": "#e74c3c",
    "Yellow": "#f1c40f",
    "Green": "#27ae60",
}


def _render_html(stats: dict, findings: list) -> str:
    esc = html.escape
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    c = stats["computers"]
    s = stats["shares"]
    d = stats["directories"]
    f = stats["files"]
    fc = stats["findings"]

    def _stat_card(label, done, total):
        return (
            f'<div class="card">'
            f'<div class="card-value">{done:,} / {total:,}</div>'
            f'<div class="card-label">{esc(label)}</div>'
            f'</div>'
        )

    def _badge(triage, clickable=False):
        color = TRIAGE_HTML_COLORS.get(triage, "#888")
        data = f' data-triage="{esc(triage)}"' if clickable else ''
        return f'<span class="badge"{data} style="background:{color}">{esc(triage)}</span>'

    cards = (
        _stat_card("Computers", c["done"], c["total"])
        + _stat_card("Shares", s["done"], s["total"])
        + _stat_card("Directories", d["walked"], d["total"])
        + _stat_card("Files", f["checked"], f["total"])
    )

    severity_badges = ""
    for name in ("Black", "Red", "Yellow", "Green"):
        count = fc.get(name.lower(), 0)
        severity_badges += (
            f'<div class="severity">{_badge(name, clickable=True)} <span>{count:,}</span></div>\n'
        )

    # Full match/context stored in a JS array for the modal (keyed by row index).
    # Prevents large text from bloating data-* attributes and keeps them out of
    # the visible DOM where truncation tests can check them independently.
    modal_data_json = json.dumps([
        {
            "match": finding.get("match_text") or "",
            "context": finding.get("context") or "",
        }
        for finding in findings
    ]).replace("</", "<\\/")  # prevent </script> injection

    rows = ""
    for idx, finding in enumerate(findings):
        triage = finding["triage"]
        ctx = finding.get("context") or ""
        match_text = finding.get("match_text") or ""
        size = finding["size"]
        size_str = format_size(size) if size is not None else ""
        mtime_str = str(finding.get('mtime') or '')

        ctx_display = ctx[:200] + ("…" if len(ctx) > 200 else "")
        match_display = match_text[:120] + ("…" if len(match_text) > 120 else "")
        match_html = f'<span class="match">{esc(match_display)}</span>' if match_text else ""

        rows += (
            f'<tr data-idx="{idx}" data-triage="{esc(triage)}" '
            f'data-rule="{esc(finding["rule_name"])}" '
            f'data-path="{esc(finding["file_path"])}" '
            f'data-size="{esc(size_str)}" '
            f'data-mtime="{esc(mtime_str)}">'
            f"<td>{_badge(triage)}</td>"
            f"<td>{esc(finding['rule_name'])}</td>"
            f'<td class="path">{esc(finding["file_path"])}</td>'
            f"<td>{esc(size_str)}</td>"
            f"<td>{esc(mtime_str)}</td>"
            f'<td class="context">{esc(ctx_display)}{match_html}</td>'
            f"</tr>\n"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Snaffler Scan Report</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ background: #1e1e1e; color: #d4d4d4; font-family: 'Cascadia Code', 'Fira Code', monospace; margin: 0; padding: 20px; }}
  h1 {{ color: #e0e0e0; margin-bottom: 4px; }}
  h2 {{ color: #e0e0e0; margin: 20px 0 8px; }}
  .timestamp {{ color: #888; font-size: 0.85em; margin-bottom: 20px; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }}
  .card {{ background: #2d2d2d; border-radius: 8px; padding: 16px 24px; min-width: 140px; text-align: center; }}
  .card-value {{ font-size: 1.4em; font-weight: bold; color: #fff; }}
  .card-label {{ color: #888; font-size: 0.85em; margin-top: 4px; }}
  .toolbar {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; }}
  .severities {{ display: flex; gap: 16px; flex-wrap: wrap; align-items: center; }}
  .severity {{ display: flex; align-items: center; gap: 6px; font-size: 1em; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; color: #fff; font-weight: bold; font-size: 0.85em; }}
  .badge[data-triage] {{ cursor: pointer; user-select: none; transition: opacity 0.15s; }}
  .badge[data-triage].active {{ outline: 2px solid #fff; outline-offset: 1px; }}
  .badge[data-triage].dimmed {{ opacity: 0.35; }}
  #clear-filter {{ background: #333; color: #aaa; border: 1px solid #444; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-family: inherit; font-size: 0.85em; }}
  #clear-filter:hover {{ background: #444; color: #fff; }}
  #search {{ flex: 1; min-width: 200px; padding: 10px 14px; background: #2d2d2d; color: #d4d4d4; border: 1px solid #444; border-radius: 6px; font-family: inherit; font-size: 1em; outline: none; }}
  #search:focus {{ border-color: #888; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 8px 12px; border-bottom: 2px solid #444; color: #aaa; font-size: 0.8em; text-transform: uppercase; cursor: pointer; user-select: none; white-space: nowrap; }}
  th:hover {{ color: #fff; }}
  th.sort-asc::after {{ content: ' ↑'; color: #fff; }}
  th.sort-desc::after {{ content: ' ↓'; color: #fff; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #2a2a2a; vertical-align: top; }}
  tbody tr {{ cursor: pointer; transition: filter 0.1s; }}
  tbody tr:hover {{ filter: brightness(1.3); }}
  tr[data-triage="Black"] {{ background: #271515; }}
  tr[data-triage="Red"] {{ background: #221212; }}
  tr[data-triage="Yellow"] {{ background: #201e0d; }}
  tr[data-triage="Green"] {{ background: #131d13; }}
  .path {{ word-break: break-all; max-width: 320px; }}
  .match {{ display: block; margin-top: 4px; font-size: 0.8em; color: #ffd700; background: #1e1900; border-left: 2px solid #ffd700; padding: 2px 6px; word-break: break-all; }}
  .context {{ font-size: 0.82em; color: #999; max-width: 280px; word-break: break-all; }}
  .footer {{ margin-top: 30px; color: #555; font-size: 0.8em; border-top: 1px solid #333; padding-top: 10px; }}
  /* Modal */
  .overlay {{ position: fixed; inset: 0; background: rgba(0,0,0,0.75); display: flex; align-items: center; justify-content: center; z-index: 1000; padding: 20px; }}
  .overlay.hidden {{ display: none; }}
  .modal {{ background: #252525; border-radius: 10px; padding: 28px 32px; width: 100%; max-width: 820px; max-height: 88vh; overflow-y: auto; position: relative; border: 1px solid #3a3a3a; }}
  .modal-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }}
  .modal-rule {{ flex: 1; font-size: 1em; font-weight: bold; color: #e0e0e0; word-break: break-all; }}
  .modal-close {{ background: none; border: none; color: #666; font-size: 1.5em; cursor: pointer; line-height: 1; padding: 0; flex-shrink: 0; }}
  .modal-close:hover {{ color: #fff; }}
  .modal-field {{ margin-bottom: 14px; }}
  .modal-field label {{ color: #666; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 4px; }}
  .modal-path {{ word-break: break-all; display: flex; gap: 10px; align-items: flex-start; }}
  .modal-path span {{ flex: 1; }}
  .copy-btn {{ background: #333; border: 1px solid #555; color: #aaa; border-radius: 4px; padding: 2px 8px; font-size: 0.75em; cursor: pointer; flex-shrink: 0; font-family: inherit; }}
  .copy-btn:hover {{ background: #444; color: #fff; }}
  .modal-meta {{ display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 14px; }}
  .modal-match {{ background: #1a1500; border-left: 3px solid #ffd700; padding: 10px 14px; color: #ffd700; white-space: pre-wrap; word-break: break-all; font-size: 0.88em; border-radius: 0 4px 4px 0; }}
  .modal-context {{ background: #1a1a1a; border-left: 3px solid #444; padding: 10px 14px; color: #aaa; white-space: pre-wrap; word-break: break-all; font-size: 0.85em; border-radius: 0 4px 4px 0; }}
</style>
</head>
<body>
<h1>Snaffler Scan Report</h1>
<div class="timestamp">Generated {esc(timestamp)}</div>

<div class="cards">
{cards}
</div>

<div class="toolbar">
  <div class="severities">
{severity_badges}  </div>
  <button id="clear-filter">Show All</button>
  <input id="search" type="text" placeholder="Filter findings..." />
</div>

<h2>Findings ({fc['total']:,})</h2>
<table id="tbl">
<thead><tr>
  <th data-col="0">Triage</th>
  <th data-col="1">Rule</th>
  <th data-col="2">Path</th>
  <th data-col="3">Size</th>
  <th data-col="4">Modified</th>
  <th data-col="5">Context</th>
</tr></thead>
<tbody>
{rows}</tbody>
</table>

<div class="footer">Generated by snaffler-ng</div>

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
var MODAL_DATA = {modal_data_json};
var activeTriage = null;
var TRIAGE_ORDER = {{'Black':0,'Red':1,'Yellow':2,'Green':3}};
var TRIAGE_COLOR = {{'Black':'#888','Red':'#e74c3c','Yellow':'#f1c40f','Green':'#27ae60'}};

// ── Severity filter ──────────────────────────────────────────────
document.querySelectorAll('.badge[data-triage]').forEach(function(badge) {{
  badge.addEventListener('click', function() {{
    var t = this.getAttribute('data-triage');
    activeTriage = (activeTriage === t) ? null : t;
    syncBadges();
    applyFilter();
  }});
}});

document.getElementById('clear-filter').addEventListener('click', function() {{
  activeTriage = null;
  syncBadges();
  applyFilter();
}});

function syncBadges() {{
  document.querySelectorAll('.badge[data-triage]').forEach(function(b) {{
    var t = b.getAttribute('data-triage');
    b.classList.toggle('active', activeTriage === t);
    b.classList.toggle('dimmed', activeTriage !== null && activeTriage !== t);
  }});
}}

// ── Search + filter ──────────────────────────────────────────────
document.getElementById('search').addEventListener('input', applyFilter);

function applyFilter() {{
  var term = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#tbl tbody tr').forEach(function(row) {{
    var triageOk = !activeTriage || row.getAttribute('data-triage') === activeTriage;
    var textOk = !term || row.textContent.toLowerCase().indexOf(term) !== -1;
    row.style.display = (triageOk && textOk) ? '' : 'none';
  }});
}}

// ── Sortable columns ─────────────────────────────────────────────
var sortCol = -1, sortAsc = true;
document.querySelectorAll('th[data-col]').forEach(function(th) {{
  th.addEventListener('click', function() {{
    var col = parseInt(this.getAttribute('data-col'));
    sortAsc = (sortCol === col) ? !sortAsc : true;
    sortCol = col;
    document.querySelectorAll('th').forEach(function(h) {{ h.classList.remove('sort-asc', 'sort-desc'); }});
    th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
    var tbody = document.querySelector('#tbl tbody');
    var rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort(function(a, b) {{
      if (col === 0) {{
        var ao = TRIAGE_ORDER[a.getAttribute('data-triage')];
        var bo = TRIAGE_ORDER[b.getAttribute('data-triage')];
        return sortAsc ? (ao - bo) : (bo - ao);
      }}
      var av = a.cells[col] ? a.cells[col].textContent.trim() : '';
      var bv = b.cells[col] ? b.cells[col].textContent.trim() : '';
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    }});
    rows.forEach(function(r) {{ tbody.appendChild(r); }});
  }});
}});

// ── Modal ────────────────────────────────────────────────────────
var overlay = document.getElementById('overlay');

document.querySelectorAll('#tbl tbody tr').forEach(function(row) {{
  row.addEventListener('click', function() {{
    var idx = parseInt(this.getAttribute('data-idx'));
    var data = MODAL_DATA[idx];
    var triage = this.getAttribute('data-triage');
    var color = TRIAGE_COLOR[triage] || '#888';
    document.getElementById('m-badge').innerHTML =
      '<span class="badge" style="background:' + color + '">' + triage + '</span>';
    document.getElementById('m-rule').textContent = this.getAttribute('data-rule');
    document.getElementById('m-path').textContent = this.getAttribute('data-path');
    document.getElementById('m-size').textContent = this.getAttribute('data-size');
    document.getElementById('m-mtime').textContent = this.getAttribute('data-mtime');
    var matchWrap = document.getElementById('m-match-wrap');
    if (data.match) {{
      document.getElementById('m-match').textContent = data.match;
      matchWrap.style.display = '';
    }} else {{
      matchWrap.style.display = 'none';
    }}
    document.getElementById('m-context').textContent = data.context;
    overlay.classList.remove('hidden');
  }});
}});

document.getElementById('modal-close').addEventListener('click', function() {{
  overlay.classList.add('hidden');
}});
overlay.addEventListener('click', function(e) {{
  if (e.target === overlay) overlay.classList.add('hidden');
}});
document.addEventListener('keydown', function(e) {{
  if (e.key === 'Escape') overlay.classList.add('hidden');
}});
document.getElementById('copy-path').addEventListener('click', function(e) {{
  e.stopPropagation();
  navigator.clipboard.writeText(document.getElementById('m-path').textContent);
  var btn = this;
  btn.textContent = 'Copied!';
  setTimeout(function() {{ btn.textContent = 'Copy'; }}, 1500);
}});
</script>
</body>
</html>"""


@results_app.callback(invoke_without_command=True)
def results(
    state: Path = typer.Option(
        Path("snaffler.db"),
        "-s", "--state",
        help="Path to the scan state database",
    ),
    fmt: Optional[str] = typer.Option(
        "plain",
        "-f", "--format",
        help="Output format",
        click_type=click.Choice(["plain", "json", "html"], case_sensitive=False),
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
    ),
    min_interest: int = typer.Option(
        0,
        "-b", "--min-interest",
        help="Minimum severity to show (0=all, 1=Yellow+, 2=Red+, 3=Black only)",
        min=0,
        max=3,
    ),
):
    conn = _open_db(state)
    try:
        stats = _query_stats(conn)
        findings = _query_findings(conn, min_interest)
    finally:
        conn.close()

    if fmt == "json":
        _render_json(stats, findings)
    elif fmt == "html":
        typer.echo(_render_html(stats, findings))
    else:
        use_color = not no_color and sys.stdout.isatty()
        _render_plain(stats, findings, use_color)
