"""Tests for the live web dashboard server."""

import json
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

flask = pytest.importorskip("flask")

from snaffler.utils.progress import ProgressState
from snaffler.web.server import create_app, _check_flask, _detect_phase


# ── Fixtures ─────────────────────────────────────────────────────

def _create_schema(conn):
    """Create the minimal scan state schema for testing."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sync
            (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS target_computer
            (name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT,
             done INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS target_share
            (unc_path TEXT PRIMARY KEY COLLATE NOCASE,
             done INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS target_dir
            (unc_path TEXT PRIMARY KEY COLLATE NOCASE,
             share TEXT NOT NULL COLLATE NOCASE,
             walked INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS target_file
            (unc_path TEXT PRIMARY KEY COLLATE NOCASE,
             share TEXT NOT NULL COLLATE NOCASE,
             size INTEGER, mtime REAL,
             checked INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS finding (
            finding_id TEXT PRIMARY KEY,
            file_path  TEXT NOT NULL,
            triage     TEXT NOT NULL,
            rule_name  TEXT NOT NULL,
            match_text TEXT,
            context    TEXT,
            size       INTEGER,
            mtime      TEXT,
            found_at   TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_finding_triage ON finding(triage);
    """)


@pytest.fixture
def db_path(tmp_path):
    """Create a temp SQLite DB with the scan state schema."""
    path = tmp_path / "test.db"
    conn = sqlite3.connect(str(path))
    _create_schema(conn)
    conn.close()
    return str(path)


@pytest.fixture
def progress():
    return ProgressState()


@pytest.fixture
def start_time():
    return datetime(2026, 1, 15, 10, 0, 0)


@pytest.fixture
def client(progress, db_path, start_time):
    """Flask test client."""
    app = create_app(progress, db_path, start_time)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── Helper ───────────────────────────────────────────────────────

def _insert_finding(db_path, finding_id, file_path, triage, rule_name,
                    match_text=None, context=None, size=None, mtime=None):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO finding (finding_id, file_path, triage, rule_name, "
        "match_text, context, size, mtime, found_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (finding_id, file_path, triage, rule_name, match_text, context,
         size, mtime, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def _insert_computer(db_path, name, ip=None, done=0):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO target_computer (name, ip, done) VALUES (?, ?, ?)",
        (name, ip, done),
    )
    conn.commit()
    conn.close()


def _insert_share(db_path, unc_path, done=0):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO target_share (unc_path, done) VALUES (?, ?)",
        (unc_path, done),
    )
    conn.commit()
    conn.close()


# ── Dashboard page ───────────────────────────────────────────────

def test_dashboard_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Snaffler Live" in resp.data


def test_dashboard_contains_key_elements(client):
    resp = client.get("/")
    html = resp.data.decode()
    assert "api/progress" in html
    assert "api/findings" in html
    assert "phase-dot" in html
    assert "card-files" in html


# ── Progress endpoint ────────────────────────────────────────────

def test_progress_idle(client, progress):
    resp = client.get("/api/progress")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["phase"] == "idle"
    assert data["dns_total"] == 0
    assert data["files_scanned"] == 0


def test_progress_dns_phase(client, progress):
    progress.dns_total = 100
    progress.dns_resolved = 20
    progress.dns_filtered = 5
    resp = client.get("/api/progress")
    data = json.loads(resp.data)
    assert data["phase"] == "dns"
    assert data["dns_total"] == 100
    assert data["dns_resolved"] == 20


def test_progress_shares_phase(client, progress):
    progress.dns_total = 100
    progress.dns_resolved = 95
    progress.dns_filtered = 5
    progress.computers_total = 50
    progress.computers_done = 10
    resp = client.get("/api/progress")
    data = json.loads(resp.data)
    assert data["phase"] == "shares"


def test_progress_walking_phase(client, progress):
    progress.shares_total = 20
    progress.shares_walked = 5
    resp = client.get("/api/progress")
    data = json.loads(resp.data)
    assert data["phase"] == "walking"


def test_progress_scanning_phase(client, progress):
    progress.files_total = 1000
    progress.files_scanned = 500
    resp = client.get("/api/progress")
    data = json.loads(resp.data)
    assert data["phase"] == "scanning"


def test_progress_complete_phase(client, progress):
    progress.files_total = 100
    progress.files_scanned = 100
    resp = client.get("/api/progress")
    data = json.loads(resp.data)
    assert data["phase"] == "complete"


def test_progress_elapsed_seconds(client, progress, start_time):
    resp = client.get("/api/progress")
    data = json.loads(resp.data)
    assert data["elapsed_seconds"] > 0


def test_progress_severity_counts(client, progress):
    progress.severity_black = 3
    progress.severity_red = 7
    progress.severity_yellow = 15
    progress.severity_green = 42
    resp = client.get("/api/progress")
    data = json.loads(resp.data)
    assert data["severity_black"] == 3
    assert data["severity_red"] == 7
    assert data["severity_yellow"] == 15
    assert data["severity_green"] == 42


# ── Stats endpoint ───────────────────────────────────────────────

def test_stats_empty_db(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["findings"]["total"] == 0
    assert data["computers"]["total"] == 0


def test_stats_populated(client, db_path):
    _insert_computer(db_path, "HOST1", ip="10.0.0.1", done=1)
    _insert_computer(db_path, "HOST2", ip=None, done=0)
    _insert_share(db_path, "//HOST1/share1", done=1)
    _insert_finding(db_path, "f1", "//HOST1/share1/secret.txt", "Black", "KeepPassDB")
    _insert_finding(db_path, "f2", "//HOST1/share1/config.xml", "Red", "ConfigXml")

    resp = client.get("/api/stats")
    data = json.loads(resp.data)
    assert data["computers"]["total"] == 2
    assert data["computers"]["done"] == 1
    assert data["computers"]["resolved"] == 1
    assert data["shares"]["total"] == 1
    assert data["findings"]["total"] == 2
    assert data["findings"]["black"] == 1
    assert data["findings"]["red"] == 1


# ── Findings endpoint ────────────────────────────────────────────

def test_findings_empty(client):
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["findings"] == []
    assert data["max_rowid"] == 0


def test_findings_returns_all(client, db_path):
    _insert_finding(db_path, "f1", "//H/s/a.txt", "Black", "Rule1", size=1024)
    _insert_finding(db_path, "f2", "//H/s/b.txt", "Green", "Rule2", size=512)
    resp = client.get("/api/findings")
    data = json.loads(resp.data)
    assert len(data["findings"]) == 2
    assert data["max_rowid"] >= 2


def test_findings_filtered_by_min_interest(client, db_path):
    _insert_finding(db_path, "f1", "//H/s/a.txt", "Black", "Rule1")
    _insert_finding(db_path, "f2", "//H/s/b.txt", "Green", "Rule2")
    # min_interest=3 → Black only
    resp = client.get("/api/findings?min_interest=3")
    data = json.loads(resp.data)
    assert len(data["findings"]) == 1
    assert data["findings"][0]["triage"] == "Black"


def test_findings_since_rowid(client, db_path):
    _insert_finding(db_path, "f1", "//H/s/a.txt", "Red", "Rule1")
    _insert_finding(db_path, "f2", "//H/s/b.txt", "Red", "Rule2")

    # Get all first
    resp1 = client.get("/api/findings")
    data1 = json.loads(resp1.data)
    assert len(data1["findings"]) == 2
    max_rowid = data1["max_rowid"]

    # Add another finding
    _insert_finding(db_path, "f3", "//H/s/c.txt", "Yellow", "Rule3")

    # Only get new ones
    resp2 = client.get(f"/api/findings?since_rowid={max_rowid}")
    data2 = json.loads(resp2.data)
    assert len(data2["findings"]) == 1
    assert data2["findings"][0]["finding_id"] == "f3"
    assert data2["max_rowid"] > max_rowid


def test_findings_incremental_empty(client, db_path):
    _insert_finding(db_path, "f1", "//H/s/a.txt", "Red", "Rule1")
    resp1 = client.get("/api/findings")
    data1 = json.loads(resp1.data)
    max_rowid = data1["max_rowid"]

    # No new findings
    resp2 = client.get(f"/api/findings?since_rowid={max_rowid}")
    data2 = json.loads(resp2.data)
    assert len(data2["findings"]) == 0
    assert data2["max_rowid"] == max_rowid


def test_findings_size_str_formatting(client, db_path):
    _insert_finding(db_path, "f1", "//H/s/a.txt", "Red", "Rule1", size=2048)
    resp = client.get("/api/findings")
    data = json.loads(resp.data)
    assert data["findings"][0]["size_str"] == "2.0 KB"


def test_findings_size_str_none(client, db_path):
    _insert_finding(db_path, "f1", "//H/s/a.txt", "Red", "Rule1", size=None)
    resp = client.get("/api/findings")
    data = json.loads(resp.data)
    assert data["findings"][0]["size_str"] == ""


# ── Phase detection ──────────────────────────────────────────────

def test_detect_phase_idle():
    p = ProgressState()
    assert _detect_phase(p) == "idle"


def test_detect_phase_dns():
    p = ProgressState()
    p.dns_total = 50
    assert _detect_phase(p) == "dns"


def test_detect_phase_shares():
    p = ProgressState()
    p.dns_total = 50
    p.dns_resolved = 50
    p.computers_total = 50
    p.computers_done = 10
    assert _detect_phase(p) == "shares"


def test_detect_phase_walking():
    p = ProgressState()
    p.shares_total = 10
    p.shares_walked = 3
    assert _detect_phase(p) == "walking"


def test_detect_phase_scanning():
    p = ProgressState()
    p.files_total = 500
    p.files_scanned = 200
    assert _detect_phase(p) == "scanning"


def test_detect_phase_complete():
    p = ProgressState()
    p.files_total = 100
    p.files_scanned = 100
    assert _detect_phase(p) == "complete"


# ── Import guard ─────────────────────────────────────────────────

def test_check_flask_succeeds():
    # Flask is installed in test env
    result = _check_flask()
    assert result is not None


def test_check_flask_import_error():
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "flask":
            raise ImportError("No module named 'flask'")
        return real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", side_effect=mock_import):
        with pytest.raises(ImportError, match="pip install snaffler-ng\\[web\\]"):
            _check_flask()


# ── Werkzeug logging suppression ─────────────────────────────────

def test_werkzeug_logging_suppressed(progress, db_path, start_time):
    import logging
    create_app(progress, db_path, start_time)
    werkzeug_logger = logging.getLogger("werkzeug")
    assert werkzeug_logger.level >= logging.ERROR
