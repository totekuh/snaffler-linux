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
    share_stats = _count("target_share", "done", 1)
    try:
        unreadable = conn.execute(
            "SELECT COUNT(*) FROM target_share WHERE readable = 0"
        ).fetchone()[0]
    except Exception:
        unreadable = 0
    share_stats["unreadable"] = unreadable
    stats["shares"] = share_stats

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


def _query_unreadable_shares(conn: sqlite3.Connection) -> list:
    try:
        rows = conn.execute(
            "SELECT unc_path FROM target_share WHERE readable = 0 ORDER BY unc_path"
        ).fetchall()
        return [row[0] for row in rows]
    except Exception:
        return []


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


def _render_plain(stats: dict, findings: list, unreadable_shares: list, use_color: bool):
    lines = []

    lines.append(f"{'── Stats ':─<50}")
    c = stats["computers"]
    lines.append(
        f"Computers:   {c['total']:,} discovered, {c['resolved']:,} resolved, {c['done']:,} done"
    )
    s = stats["shares"]
    share_line = f"Shares:      {s['total']:,} discovered, {s['done']:,} done"
    if s.get("unreadable"):
        share_line += f", {s['unreadable']:,} unreadable"
    lines.append(share_line)
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

    if unreadable_shares:
        lines.append("")
        lines.append(f"{'── Unreadable Shares (' + str(len(unreadable_shares)) + ') ':─<50}")
        lines.append(" Use --rescan-unreadable with new creds to retry these:")
        for share in unreadable_shares:
            lines.append(f"  {share}")

    typer.echo("\n".join(lines))


def _render_json(stats: dict, findings: list, unreadable_shares: list):
    output = {"stats": stats, "findings": findings, "unreadable_shares": unreadable_shares}
    typer.echo(json.dumps(output, indent=2, default=str))


TRIAGE_HTML_COLORS = {
    "Black": "#888",
    "Red": "#e74c3c",
    "Yellow": "#f1c40f",
    "Green": "#27ae60",
}


def _render_unreadable_html(shares: list) -> str:
    if not shares:
        return ""
    esc = html.escape
    items = "\n".join(f"<li>{esc(s)}</li>" for s in shares)
    return (
        f'<h2>Unreadable Shares ({len(shares):,})</h2>'
        f'<p style="color:#888;font-size:0.85em;">Use <code>--rescan-unreadable</code> with new creds to retry these.</p>'
        f'<ul style="color:#e74c3c;font-size:0.9em;">{items}</ul>'
    )


def _render_html(stats: dict, findings: list, unreadable_shares: list | None = None) -> str:
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

    def _stat_card_sub(label, done, total, sub_label=None, sub_value=None):
        sub = ""
        if sub_value:
            sub = f'<div class="card-sub">{sub_value:,} {esc(sub_label)}</div>'
        return (
            f'<div class="card">'
            f'<div class="card-value">{done:,} / {total:,}</div>'
            f'<div class="card-label">{esc(label)}</div>'
            f'{sub}'
            f'</div>'
        )

    cards = (
        _stat_card("Computers", c["done"], c["total"])
        + _stat_card_sub("Shares", s["done"], s["total"], "unreadable", s.get("unreadable", 0))
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

        finding_id = finding.get("finding_id") or f"f{idx}"
        # Extract host from UNC path (//HOST/SHARE/...) or FTP URL (ftp://HOST:PORT/...)
        file_path = finding["file_path"]
        host = ""
        if file_path.startswith("//"):
            parts = file_path.split("/")
            if len(parts) >= 3:
                host = parts[2]
        elif file_path.startswith("ftp://"):
            rest = file_path[6:]
            slash_idx = rest.find("/")
            host = rest[:slash_idx] if slash_idx != -1 else rest

        rows += (
            f'<tr data-idx="{idx}" data-id="{esc(finding_id)}" data-triage="{esc(triage)}" '
            f'data-rule="{esc(finding["rule_name"])}" '
            f'data-host="{esc(host)}" '
            f'data-path="{esc(file_path)}" '
            f'data-size="{esc(size_str)}" '
            f'data-mtime="{esc(mtime_str)}" data-status="">'
            f'<td class="status-cell"></td>'
            f"<td>{_badge(triage)}</td>"
            f"<td>{esc(finding['rule_name'])}</td>"
            f"<td>{esc(host)}</td>"
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
  .card-sub {{ color: #e74c3c; font-size: 0.8em; margin-top: 2px; }}
  .toolbar {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 16px; }}
  .severities {{ display: flex; gap: 16px; flex-wrap: wrap; align-items: center; }}
  .severity {{ display: flex; align-items: center; gap: 6px; font-size: 1em; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; color: #fff; font-weight: bold; font-size: 0.85em; }}
  .badge[data-triage] {{ cursor: pointer; user-select: none; transition: opacity 0.15s; }}
  .badge[data-triage].active {{ outline: 2px solid #fff; outline-offset: 1px; }}
  .badge[data-triage].dimmed {{ opacity: 0.35; }}
  #clear-filter {{ background: #333; color: #aaa; border: 1px solid #444; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-family: inherit; font-size: 0.85em; }}
  #clear-filter:hover {{ background: #444; color: #fff; }}
  .filter-row th {{ padding: 4px 4px; border-bottom: 2px solid #444; cursor: default; }}
  .filter-row th:hover {{ color: #aaa; }}
  .filter-cell {{ display: flex; gap: 2px; }}
  .col-filter {{ flex: 1; min-width: 0; padding: 4px 6px; background: #252525; color: #d4d4d4; border: 1px solid #3a3a3a; border-radius: 4px; font-family: inherit; font-size: 0.8em; outline: none; box-sizing: border-box; }}
  .col-filter:focus {{ border-color: #888; background: #2d2d2d; }}
  .col-filter::placeholder {{ color: #555; }}
  .col-select {{ width: 24px; flex-shrink: 0; padding: 0; background: #252525; color: #888; border: 1px solid #3a3a3a; border-radius: 4px; font-family: inherit; font-size: 0.8em; outline: none; cursor: pointer; appearance: none; -webkit-appearance: none; text-align: center; }}
  .col-select:focus {{ border-color: #888; }}
  .col-select:hover {{ color: #d4d4d4; background: #2d2d2d; }}
  #search {{ flex: 1; min-width: 200px; padding: 10px 14px; background: #2d2d2d; color: #d4d4d4; border: 1px solid #444; border-radius: 6px; font-family: inherit; font-size: 1em; outline: none; }}
  #search:focus {{ border-color: #888; }}
  table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
  colgroup .col-status {{ width: 28px; }}
  colgroup .col-triage {{ width: 70px; }}
  colgroup .col-rule {{ width: 130px; }}
  colgroup .col-host {{ width: 130px; }}
  colgroup .col-path {{ width: 28%; }}
  colgroup .col-size {{ width: 70px; }}
  colgroup .col-mtime {{ width: 110px; }}
  colgroup .col-context {{ width: auto; }}
  thead {{ position: sticky; top: 0; z-index: 20; }}
  thead tr {{ background: #1e1e1e; }}
  th {{ text-align: left; padding: 8px 12px; border-bottom: 2px solid #444; color: #aaa; font-size: 0.8em; text-transform: uppercase; cursor: pointer; user-select: none; white-space: nowrap; position: relative; overflow: hidden; text-overflow: ellipsis; }}
  th:hover {{ color: #fff; }}
  th.sort-asc::after {{ content: ' ↑'; color: #fff; }}
  th.sort-desc::after {{ content: ' ↓'; color: #fff; }}
  .resize-handle {{ position: absolute; right: 0; top: 0; width: 5px; height: 100%; cursor: col-resize; z-index: 10; }}
  .resize-handle:hover, .resize-handle.active {{ background: #888; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #2a2a2a; vertical-align: top; overflow: hidden; text-overflow: ellipsis; }}
  tbody tr {{ cursor: pointer; transition: filter 0.1s; }}
  tbody tr:hover {{ filter: brightness(1.3); }}
  tr[data-triage="Black"] {{ background: #271515; }}
  tr[data-triage="Red"] {{ background: #221212; }}
  tr[data-triage="Yellow"] {{ background: #201e0d; }}
  tr[data-triage="Green"] {{ background: #131d13; }}
  .path {{ word-break: break-all; }}
  .match {{ display: block; margin-top: 4px; font-size: 0.8em; color: #ffd700; background: #1e1900; border-left: 2px solid #ffd700; padding: 2px 6px; word-break: break-all; }}
  .context {{ font-size: 0.82em; color: #999; word-break: break-all; }}
  .status-cell {{ width: 28px; text-align: center; padding: 8px 4px; }}
  .status-icon {{ cursor: pointer; font-size: 0.9em; opacity: 0.4; transition: opacity 0.15s; }}
  .status-icon:hover {{ opacity: 1; }}
  tr[data-status="done"] {{ opacity: 0.35; }}
  tr[data-status="done"] .status-icon {{ opacity: 1; }}
  tr[data-status="review"] .status-icon {{ opacity: 1; }}
  .status-btns {{ display: flex; gap: 8px; align-items: center; }}
  .status-btn {{ background: #333; color: #aaa; border: 1px solid #444; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-family: inherit; font-size: 0.85em; transition: all 0.15s; }}
  .status-btn:hover {{ background: #444; color: #fff; }}
  .status-btn.active {{ outline: 2px solid #fff; outline-offset: 1px; color: #fff; }}
  .modal-actions {{ display: flex; gap: 10px; margin-top: 18px; padding-top: 14px; border-top: 1px solid #333; }}
  .modal-action {{ background: #333; color: #ccc; border: 1px solid #555; border-radius: 6px; padding: 8px 16px; cursor: pointer; font-family: inherit; font-size: 0.85em; }}
  .modal-action:hover {{ background: #444; color: #fff; }}
  .modal-action.active {{ background: #444; color: #fff; border-color: #888; }}
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
  <div class="status-btns">
    <button class="status-btn" data-status-filter="review">Review Later</button>
    <button class="status-btn" data-status-filter="done">Done</button>
    <button class="status-btn" data-status-filter="hide-done">Hide Done</button>
  </div>
  <button id="clear-filter">Show All</button>
  <input id="search" type="text" placeholder="Filter findings (searches match &amp; context)..." />
</div>

<h2>Findings (<span id="findings-visible">{fc['total']:,}</span> / {fc['total']:,})</h2>
<table id="tbl">
<colgroup>
  <col class="col-status">
  <col class="col-triage">
  <col class="col-rule">
  <col class="col-host">
  <col class="col-path">
  <col class="col-size">
  <col class="col-mtime">
  <col class="col-context">
</colgroup>
<thead>
<tr>
  <th data-col="0"></th>
  <th data-col="1">Triage<div class="resize-handle"></div></th>
  <th data-col="2">Rule<div class="resize-handle"></div></th>
  <th data-col="3">Host<div class="resize-handle"></div></th>
  <th data-col="4">Path<div class="resize-handle"></div></th>
  <th data-col="5">Size<div class="resize-handle"></div></th>
  <th data-col="6">Modified<div class="resize-handle"></div></th>
  <th data-col="7">Context</th>
</tr>
<tr class="filter-row">
  <th></th>
  <th></th>
  <th><div class="filter-cell"><input class="col-filter" id="f-rule" placeholder="rule..." /><select class="col-select" id="s-rule" title="Pick rule">&#9662;</select></div></th>
  <th><div class="filter-cell"><input class="col-filter" id="f-host" placeholder="host..." /><select class="col-select" id="s-host" title="Pick host">&#9662;</select></div></th>
  <th><input class="col-filter" id="f-path" placeholder="path..." /></th>
  <th></th>
  <th></th>
  <th><input class="col-filter" id="f-context" placeholder="context..." /></th>
</tr>
</thead>
<tbody>
{rows}</tbody>
</table>

{_render_unreadable_html(unreadable_shares or [])}
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
    <div class="modal-field" id="m-cmd-wrap">
      <label>Connect</label>
      <div class="modal-path">
        <code id="m-cmd" style="flex:1; color:#7ec8e3; font-size:0.9em;"></code>
        <button class="copy-btn" id="copy-cmd">Copy</button>
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
    <div class="modal-actions">
      <button class="modal-action" id="m-review">Review Later</button>
      <button class="modal-action" id="m-done">Mark Done</button>
      <button class="modal-action" id="m-clear-status">Clear Status</button>
    </div>
  </div>
</div>

<script>
var MODAL_DATA = {modal_data_json};
var activeTriage = null;
var activeStatus = "";  // "", "review", "done", "hide-done"
var TRIAGE_ORDER = {{'Black':0,'Red':1,'Yellow':2,'Green':3}};
var TRIAGE_COLOR = {{'Black':'#888','Red':'#e74c3c','Yellow':'#f1c40f','Green':'#27ae60'}};
var STATUS_ICONS = {{'': '\u2022', 'review': '\u2691', 'done': '\u2713'}};
var currentModalRow = null;

// ── localStorage persistence ─────────────────────────────────────
var LS_KEY = 'snaffler_finding_status';
function loadStatuses() {{
  try {{ return JSON.parse(localStorage.getItem(LS_KEY)) || {{}}; }}
  catch(e) {{ return {{}}; }}
}}
function saveStatuses(obj) {{
  localStorage.setItem(LS_KEY, JSON.stringify(obj));
}}

function setStatus(findingId, status) {{
  var statuses = loadStatuses();
  if (status) {{ statuses[findingId] = status; }}
  else {{ delete statuses[findingId]; }}
  saveStatuses(statuses);
}}

function getStatus(findingId) {{
  return loadStatuses()[findingId] || "";
}}

// ── Status cell rendering ────────────────────────────────────────
function renderStatusCell(td, status) {{
  var icon = STATUS_ICONS[status] || STATUS_ICONS[''];
  var color = status === 'done' ? '#27ae60' : status === 'review' ? '#e67e22' : '#555';
  var title = status === 'done' ? 'Done' : status === 'review' ? 'Review later' : 'No status';
  td.innerHTML = '<span class="status-icon" style="color:' + color + '" title="' + title + '">' + icon + '</span>';
}}

// ── Init: restore statuses from localStorage ─────────────────────
document.querySelectorAll('#tbl tbody tr').forEach(function(row) {{
  var fid = row.getAttribute('data-id');
  var status = getStatus(fid);
  row.setAttribute('data-status', status);
  renderStatusCell(row.querySelector('.status-cell'), status);

  // Click status icon to cycle: none → review → done → none
  row.querySelector('.status-icon').addEventListener('click', function(e) {{
    e.stopPropagation();
    var cur = row.getAttribute('data-status');
    var next = cur === '' ? 'review' : cur === 'review' ? 'done' : '';
    row.setAttribute('data-status', next);
    setStatus(fid, next);
    renderStatusCell(row.querySelector('.status-cell'), next);
    applyFilter();
  }});
}});


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
  activeStatus = "";
  document.getElementById('search').value = "";
  document.querySelectorAll('.col-filter').forEach(function(f) {{ f.value = ""; }});
  document.querySelectorAll('.col-select').forEach(function(s) {{ s.value = ""; }});
  document.querySelectorAll('.status-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  syncBadges();
  applyFilter();
}});

// ── Inline column filters + select dropdowns ──────────────────────
(function() {{
  var seenHost = {{}}, seenRule = {{}};
  document.querySelectorAll('#tbl tbody tr').forEach(function(row) {{
    var h = row.getAttribute('data-host') || '';
    var r = row.getAttribute('data-rule') || '';
    if (h) seenHost[h] = true;
    if (r) seenRule[r] = true;
  }});
  function fillSelect(selId, inputId, obj) {{
    var sel = document.getElementById(selId);
    var inp = document.getElementById(inputId);
    // first option is the arrow label (already in HTML), replace with "All"
    sel.innerHTML = '<option value="">All</option>';
    Object.keys(obj).sort().forEach(function(v) {{
      var opt = document.createElement('option');
      opt.value = v;
      opt.textContent = v;
      sel.appendChild(opt);
    }});
    sel.addEventListener('change', function() {{
      inp.value = this.value;
      applyFilter();
    }});
  }}
  fillSelect('s-host', 'f-host', seenHost);
  fillSelect('s-rule', 'f-rule', seenRule);
}})();

document.querySelectorAll('.col-filter').forEach(function(input) {{
  input.addEventListener('input', function() {{
    // clear the paired select when typing manually
    var sel = this.parentElement && this.parentElement.querySelector('.col-select');
    if (sel) sel.value = '';
    applyFilter();
  }});
  // prevent clicking a filter input from triggering column sort
  input.addEventListener('click', function(e) {{ e.stopPropagation(); }});
}});
document.querySelectorAll('.col-select').forEach(function(sel) {{
  sel.addEventListener('click', function(e) {{ e.stopPropagation(); }});
}});

// ── Status filter buttons ────────────────────────────────────────
document.querySelectorAll('.status-btn[data-status-filter]').forEach(function(btn) {{
  btn.addEventListener('click', function() {{
    var f = this.getAttribute('data-status-filter');
    activeStatus = (activeStatus === f) ? "" : f;
    document.querySelectorAll('.status-btn').forEach(function(b) {{
      b.classList.toggle('active', b.getAttribute('data-status-filter') === activeStatus);
    }});
    applyFilter();
  }});
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
  var fRule = (document.getElementById('f-rule').value || '').toLowerCase();
  var fHost = (document.getElementById('f-host').value || '').toLowerCase();
  var fPath = (document.getElementById('f-path').value || '').toLowerCase();
  var fCtx  = (document.getElementById('f-context').value || '').toLowerCase();
  var visible = 0;
  document.querySelectorAll('#tbl tbody tr').forEach(function(row) {{
    var triageOk = !activeTriage || row.getAttribute('data-triage') === activeTriage;
    var ruleOk = !fRule || (row.getAttribute('data-rule') || '').toLowerCase().indexOf(fRule) !== -1;
    var hostOk = !fHost || (row.getAttribute('data-host') || '').toLowerCase().indexOf(fHost) !== -1;
    var pathOk = !fPath || (row.getAttribute('data-path') || '').toLowerCase().indexOf(fPath) !== -1;
    var rowStatus = row.getAttribute('data-status') || '';
    var statusOk = true;
    if (activeStatus === 'review') {{ statusOk = rowStatus === 'review'; }}
    else if (activeStatus === 'done') {{ statusOk = rowStatus === 'done'; }}
    else if (activeStatus === 'hide-done') {{ statusOk = rowStatus !== 'done'; }}
    var ctxOk = true;
    if (fCtx) {{
      var idx = parseInt(row.getAttribute('data-idx'));
      var data = MODAL_DATA[idx] || {{}};
      var ctxHay = ((data.context || '') + '\\n' + (data.match || '')).toLowerCase();
      ctxOk = ctxHay.indexOf(fCtx) !== -1;
    }}
    var textOk = true;
    if (term) {{
      var idx2 = parseInt(row.getAttribute('data-idx'));
      var data2 = MODAL_DATA[idx2] || {{}};
      var haystack = row.textContent.toLowerCase()
        + "\\n" + (data2.match || "").toLowerCase()
        + "\\n" + (data2.context || "").toLowerCase();
      textOk = haystack.indexOf(term) !== -1;
    }}
    var show = triageOk && ruleOk && hostOk && pathOk && ctxOk && statusOk && textOk;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
  }});
  document.getElementById('findings-visible').textContent = visible.toLocaleString();
}}

// ── Sortable columns ─────────────────────────────────────────────
var sortCol = -1, sortAsc = true;
document.querySelectorAll('th[data-col]').forEach(function(th) {{
  th.addEventListener('click', function() {{
    var col = parseInt(this.getAttribute('data-col'));
    if (col === 0) return;  // status column not sortable
    sortAsc = (sortCol === col) ? !sortAsc : true;
    sortCol = col;
    document.querySelectorAll('th').forEach(function(h) {{ h.classList.remove('sort-asc', 'sort-desc'); }});
    th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
    var tbody = document.querySelector('#tbl tbody');
    var rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort(function(a, b) {{
      if (col === 1) {{
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

function syncModalActions() {{
  if (!currentModalRow) return;
  var s = currentModalRow.getAttribute('data-status') || '';
  document.getElementById('m-review').classList.toggle('active', s === 'review');
  document.getElementById('m-done').classList.toggle('active', s === 'done');
}}

document.querySelectorAll('#tbl tbody tr').forEach(function(row) {{
  row.addEventListener('click', function() {{
    currentModalRow = this;
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
    var cmd = buildConnectCmd(this.getAttribute('data-path'));
    var cmdWrap = document.getElementById('m-cmd-wrap');
    if (cmd) {{
      document.getElementById('m-cmd').textContent = cmd;
      cmdWrap.style.display = '';
    }} else {{
      cmdWrap.style.display = 'none';
    }}
    var matchWrap = document.getElementById('m-match-wrap');
    if (data.match) {{
      document.getElementById('m-match').textContent = data.match;
      matchWrap.style.display = '';
    }} else {{
      matchWrap.style.display = 'none';
    }}
    document.getElementById('m-context').textContent = data.context;
    syncModalActions();
    overlay.classList.remove('hidden');
  }});
}});

function setModalStatus(status) {{
  if (!currentModalRow) return;
  var fid = currentModalRow.getAttribute('data-id');
  var cur = currentModalRow.getAttribute('data-status');
  var next = (cur === status) ? '' : status;
  currentModalRow.setAttribute('data-status', next);
  setStatus(fid, next);
  renderStatusCell(currentModalRow.querySelector('.status-cell'), next);
  syncModalActions();
  applyFilter();
}}

document.getElementById('m-review').addEventListener('click', function() {{ setModalStatus('review'); }});
document.getElementById('m-done').addEventListener('click', function() {{ setModalStatus('done'); }});
document.getElementById('m-clear-status').addEventListener('click', function() {{ setModalStatus(''); }});

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

function buildConnectCmd(path) {{
  // UNC: //HOST/SHARE/... → impacket-smbclient HOST -k -no-pass
  // FTP: ftp://HOST:PORT/... → ftp HOST PORT
  // Local: /path/... → no command
  if (path.startsWith('ftp://')) {{
    var rest = path.slice(6);
    var slashIdx = rest.indexOf('/');
    var hostPort = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    var parts = hostPort.split(':');
    var host = parts[0];
    var port = parts[1] || '21';
    return port === '21' ? 'ftp ' + host : 'ftp ' + host + ' ' + port;
  }}
  if (path.startsWith('//')) {{
    var parts = path.split('/');
    // parts: ["", "", HOST, SHARE, ...]
    if (parts.length >= 3) {{
      return 'impacket-smbclient ' + parts[2] + ' -k -no-pass';
    }}
  }}
  return '';
}}

document.getElementById('copy-cmd').addEventListener('click', function(e) {{
  e.stopPropagation();
  navigator.clipboard.writeText(document.getElementById('m-cmd').textContent);
  var btn = this;
  btn.textContent = 'Copied!';
  setTimeout(function() {{ btn.textContent = 'Copy'; }}, 1500);
}});

// ── Column resize ─────────────────────────────────────────────────
(function() {{
  var tbl = document.getElementById('tbl');
  var cols = tbl.querySelectorAll('colgroup col');
  var handles = tbl.querySelectorAll('.resize-handle');
  var activeHandle = null, startX = 0, startW = 0, colIdx = 0;

  handles.forEach(function(handle) {{
    handle.addEventListener('mousedown', function(e) {{
      e.preventDefault();
      e.stopPropagation();
      activeHandle = handle;
      handle.classList.add('active');
      var th = handle.parentElement;
      colIdx = parseInt(th.getAttribute('data-col'));
      startX = e.pageX;
      startW = th.offsetWidth;
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    }});
  }});

  document.addEventListener('mousemove', function(e) {{
    if (!activeHandle) return;
    var diff = e.pageX - startX;
    var newW = Math.max(40, startW + diff);
    cols[colIdx].style.width = newW + 'px';
  }});

  document.addEventListener('mouseup', function() {{
    if (!activeHandle) return;
    activeHandle.classList.remove('active');
    activeHandle = null;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }});
}})();
</script>
</body>
</html>"""


def _query_rule_counts(conn: sqlite3.Connection, min_interest: int = 0) -> list:
    """Return [(rule_name, triage, count)] sorted by count descending."""
    threshold = 3 - min_interest  # Green=0→3, Yellow=1→2, Red=2→1, Black=3→0
    allowed = [name for name, order in TRIAGE_ORDER.items() if order <= threshold]
    if not allowed:
        return []

    placeholders = ",".join("?" for _ in allowed)
    rows = conn.execute(
        f"SELECT rule_name, triage, COUNT(*) as cnt "  # noqa: S608
        f"FROM finding WHERE triage IN ({placeholders}) "
        f"GROUP BY rule_name, triage "
        f"ORDER BY cnt DESC",
        allowed,
    ).fetchall()
    return [(row[0], row[1], row[2]) for row in rows]


@results_app.callback(invoke_without_command=True)
def results(
    ctx: typer.Context,
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
    rule: Optional[list[str]] = typer.Option(
        None,
        "--rule", "-r",
        help="Filter findings by rule name (repeatable)",
    ),
    hide_unreadable: bool = typer.Option(
        False,
        "--hide-unreadable", "-hu",
        help="Hide unreadable shares section",
    ),
    files: bool = typer.Option(
        False,
        "--files",
        help="Print one file path per line (pipe into --grab)",
    ),
):
    # Store shared options for subcommands
    ctx.ensure_object(dict)
    ctx.obj["state"] = state
    ctx.obj["no_color"] = no_color
    ctx.obj["min_interest"] = min_interest

    # If a subcommand is being invoked, skip the default results display
    if ctx.invoked_subcommand is not None:
        return

    conn = _open_db(state)
    try:
        findings = _query_findings(conn, min_interest)
        if not files:
            stats = _query_stats(conn)
            unreadable = [] if hide_unreadable else _query_unreadable_shares(conn)
    finally:
        conn.close()

    # Apply --rule filter
    if rule:
        rule_set = {r.lower() for r in rule}
        findings = [f for f in findings if f["rule_name"].lower() in rule_set]

    if files:
        for f in findings:
            typer.echo(f["file_path"])
        return

    if fmt == "json":
        _render_json(stats, findings, unreadable)
    elif fmt == "html":
        typer.echo(_render_html(stats, findings, unreadable))
    else:
        use_color = not no_color and sys.stdout.isatty()
        _render_plain(stats, findings, unreadable, use_color)


@results_app.command()
def rules(
    ctx: typer.Context,
    fmt: Optional[str] = typer.Option(
        "plain",
        "-f", "--format",
        help="Output format",
        click_type=click.Choice(["plain", "json"], case_sensitive=False),
    ),
):
    """List all matching rules and their finding counts."""
    obj = ctx.ensure_object(dict)
    state = obj.get("state", Path("snaffler.db"))
    no_color = obj.get("no_color", False)
    min_interest = obj.get("min_interest", 0)

    conn = _open_db(state)
    try:
        rule_counts = _query_rule_counts(conn, min_interest)
    finally:
        conn.close()

    if fmt == "json":
        output = [
            {"rule_name": name, "triage": triage, "count": cnt}
            for name, triage, cnt in rule_counts
        ]
        typer.echo(json.dumps(output, indent=2))
        return

    if not rule_counts:
        typer.echo("No findings in database.")
        return

    use_color = not no_color and sys.stdout.isatty()
    total = sum(cnt for _, _, cnt in rule_counts)
    lines = [f"{'── Rules (' + str(len(rule_counts)) + ' rules, ' + str(total) + ' findings) ':─<60}"]

    for rule_name, triage, count in rule_counts:
        if use_color:
            color = TRIAGE_COLORS.get(triage, "")
            lines.append(f"  {color}[{triage}]{Colors.RESET} {rule_name}: {count:,}")
        else:
            lines.append(f"  [{triage}] {rule_name}: {count:,}")

    typer.echo("\n".join(lines))
