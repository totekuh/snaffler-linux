"""Flask-based live web dashboard server."""

import logging
import sqlite3
import threading
import time
from datetime import datetime

logger = logging.getLogger("snaffler")

_server_thread = None


def _check_flask():
    """Import guard — raises ImportError with install hint if Flask is missing."""
    try:
        import flask  # noqa: F401
        return flask
    except ImportError:
        raise ImportError(
            "Flask is required for --web support. "
            "Install it with: pip install snaffler-ng[web]"
        )


def _detect_phase(progress) -> str:
    """Determine the current scan phase from ProgressState counters."""
    p = progress

    # Complete: files_total > 0 and all scanned, no walking active
    walking = p.shares_total > 0 and p.shares_walked < p.shares_total
    scanning = p.files_total > 0
    scan_done = scanning and p.files_scanned >= p.files_total and not walking

    if scan_done:
        return "complete"
    if scanning and not walking:
        return "scanning"
    if walking:
        return "walking"

    # Share discovery active
    if p.computers_total > 0 and p.computers_done < p.computers_total:
        return "shares"

    # DNS active
    if p.dns_total > 0 and (p.dns_resolved + p.dns_filtered) < p.dns_total:
        return "dns"

    return "idle"


def _format_size(size):
    """Format file size for display."""
    if size is None:
        return ""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


def create_app(progress, db_path, start_time):
    """Create and configure the Flask app.

    Args:
        progress: ProgressState instance (read-only, no DB I/O)
        db_path: Path to the SQLite state database
        start_time: datetime when the scan started
    """
    flask = _check_flask()
    from snaffler.web.dashboard import render_dashboard

    app = flask.Flask(__name__)

    # Suppress werkzeug request logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    @app.route("/")
    def index():
        return render_dashboard()

    @app.route("/api/progress")
    def api_progress():
        elapsed = (datetime.now() - start_time).total_seconds()
        phase = _detect_phase(progress)

        return flask.jsonify({
            "phase": phase,
            "elapsed_seconds": int(elapsed),
            "dns_total": progress.dns_total,
            "dns_resolved": progress.dns_resolved,
            "dns_filtered": progress.dns_filtered,
            "computers_total": progress.computers_total,
            "computers_done": progress.computers_done,
            "shares_found": progress.shares_found,
            "shares_total": progress.shares_total,
            "shares_walked": progress.shares_walked,
            "files_total": progress.files_total,
            "files_scanned": progress.files_scanned,
            "files_in_progress": progress.files_in_progress,
            "severity_black": progress.severity_black,
            "severity_red": progress.severity_red,
            "severity_yellow": progress.severity_yellow,
            "severity_green": progress.severity_green,
        })

    @app.route("/api/stats")
    def api_stats():
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                from snaffler.cli.results import _query_stats
                stats = _query_stats(conn)
            finally:
                conn.close()
            return flask.jsonify(stats)
        except Exception as exc:
            return flask.jsonify({"error": str(exc)}), 500

    @app.route("/api/findings")
    def api_findings():
        min_interest = flask.request.args.get("min_interest", 0, type=int)
        since_rowid = flask.request.args.get("since_rowid", 0, type=int)

        # Map min_interest to allowed triage levels
        triage_order = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}
        threshold = 3 - min_interest
        allowed = [name for name, order in triage_order.items() if order <= threshold]

        if not allowed:
            return flask.jsonify({"findings": [], "max_rowid": since_rowid})

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                placeholders = ",".join("?" for _ in allowed)
                rows = conn.execute(
                    f"SELECT rowid, finding_id, file_path, triage, rule_name, "  # noqa: S608
                    f"match_text, context, size, mtime, found_at "
                    f"FROM finding "
                    f"WHERE triage IN ({placeholders}) AND rowid > ? "
                    f"ORDER BY rowid",
                    [*allowed, since_rowid],
                ).fetchall()

                max_rowid = since_rowid
                findings = []
                for row in rows:
                    d = dict(row)
                    rid = d.pop("rowid")
                    if rid > max_rowid:
                        max_rowid = rid
                    d["size_str"] = _format_size(d.get("size"))
                    findings.append(d)
            finally:
                conn.close()

            return flask.jsonify({"findings": findings, "max_rowid": max_rowid})
        except Exception as exc:
            return flask.jsonify({"error": str(exc), "findings": [], "max_rowid": since_rowid}), 500

    return app


def start_web_server(progress, db_path, start_time, port=8080):
    """Start the Flask web dashboard in a daemon thread.

    Args:
        progress: ProgressState instance
        db_path: Path to the SQLite state database
        start_time: datetime when the scan started
        port: Port to bind to (default 8080)
    """
    global _server_thread

    try:
        app = create_app(progress, db_path, start_time)
    except ImportError as exc:
        raise ImportError(str(exc))

    def run():
        try:
            app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
        except OSError as exc:
            logger.error(f"Web dashboard failed to start on port {port}: {exc}")

    _server_thread = threading.Thread(target=run, daemon=True, name="web-dashboard")
    _server_thread.start()

    # Give Flask a moment to bind
    time.sleep(0.2)
    logger.info(f"Web dashboard: http://127.0.0.1:{port}")


def stop_web_server():
    """Clear the server thread reference. The daemon thread dies with the process."""
    global _server_thread
    _server_thread = None
