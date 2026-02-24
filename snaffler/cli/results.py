"""snaffler results — display stats and findings from a scan database."""

import json
import sqlite3
import sys
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
            preview = ctx[:200]
            lines.append(f"  Context: {preview}...")

    typer.echo("\n".join(lines))


def _render_json(stats: dict, findings: list):
    output = {"stats": stats, "findings": findings}
    typer.echo(json.dumps(output, indent=2, default=str))


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
        click_type=click.Choice(["plain", "json"], case_sensitive=False),
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
    else:
        use_color = not no_color and sys.stdout.isatty()
        _render_plain(stats, findings, use_color)
