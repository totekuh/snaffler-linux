import json
import sqlite3
import subprocess
import sys
import textwrap

import pytest
from typer.testing import CliRunner

from snaffler.cli.main import app

runner = CliRunner()


# ---------- helpers ----------

def _create_db(path):
    """Create a minimal scan DB with schema matching SQLiteStateStore."""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE sync (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE target_computer (
            name TEXT PRIMARY KEY COLLATE NOCASE,
            ip TEXT,
            done INTEGER DEFAULT 0
        );
        CREATE TABLE target_share (
            unc_path TEXT PRIMARY KEY COLLATE NOCASE,
            done INTEGER DEFAULT 0
        );
        CREATE TABLE target_dir (
            unc_path TEXT PRIMARY KEY COLLATE NOCASE,
            share TEXT NOT NULL COLLATE NOCASE,
            walked INTEGER DEFAULT 0
        );
        CREATE TABLE target_file (
            unc_path TEXT PRIMARY KEY COLLATE NOCASE,
            share TEXT NOT NULL COLLATE NOCASE,
            size INTEGER,
            mtime REAL,
            checked INTEGER DEFAULT 0
        );
        CREATE TABLE finding (
            finding_id TEXT PRIMARY KEY,
            file_path TEXT NOT NULL,
            triage TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            match_text TEXT,
            context TEXT,
            size INTEGER,
            mtime TEXT,
            found_at TEXT NOT NULL
        );
    """)
    return conn


def _populate_db(conn):
    """Insert sample data for testing."""
    conn.executemany(
        "INSERT INTO target_computer (name, ip, done) VALUES (?, ?, ?)",
        [
            ("DC01", "10.0.0.1", 1),
            ("FS01", "10.0.0.2", 1),
            ("WEB01", None, 0),
        ],
    )
    conn.executemany(
        "INSERT INTO target_share (unc_path, done) VALUES (?, ?)",
        [
            ("//DC01/SYSVOL", 1),
            ("//DC01/NETLOGON", 1),
            ("//FS01/Data", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO target_dir (unc_path, share, walked) VALUES (?, ?, ?)",
        [
            ("//DC01/SYSVOL", "//DC01/SYSVOL", 1),
            ("//DC01/SYSVOL/scripts", "//DC01/SYSVOL", 1),
            ("//FS01/Data", "//FS01/Data", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO target_file (unc_path, share, size, mtime, checked) VALUES (?, ?, ?, ?, ?)",
        [
            ("//DC01/SYSVOL/scripts/login.bat", "//DC01/SYSVOL", 512, 1700000000, 1),
            ("//DC01/SYSVOL/scripts/map.ps1", "//DC01/SYSVOL", 1024, 1700000000, 1),
            ("//FS01/Data/report.xlsx", "//FS01/Data", 50000, 1700000000, 0),
        ],
    )
    conn.executemany(
        "INSERT INTO finding (finding_id, file_path, triage, rule_name, "
        "match_text, context, size, mtime, found_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("aaa", "//DC01/IT$/passwords.kdbx", "Black", "KeepPassKDBX",
             None, None, 2200000, "2025-01-15", "2026-02-24T10:30:00"),
            ("bbb", "//FS02/deploy$/id_rsa", "Black", "PrivateKey",
             None, "-----BEGIN RSA PRIVATE KEY-----", 1700, "2025-02-01", "2026-02-24T10:31:00"),
            ("ccc", "//WEB01/wwwroot$/web.config", "Red", "WebConfig",
             None, 'connectionString="Server=sql01;..."', 4300, "2025-03-10", "2026-02-24T10:32:00"),
            ("ddd", "//FS01/Data/notes.txt", "Yellow", "InterestingFile",
             None, None, 800, "2025-04-01", "2026-02-24T10:33:00"),
            ("eee", "//FS01/Data/readme.md", "Green", "MildlyInteresting",
             None, None, 200, "2025-05-01", "2026-02-24T10:34:00"),
        ],
    )
    conn.commit()


# ---------- tests ----------

def test_plain_output(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    _populate_db(conn)
    conn.close()

    result = runner.invoke(app, ["results", "--state", str(db_path), "--no-color"])

    assert result.exit_code == 0
    out = result.output
    # Stats section
    assert "Computers:" in out
    assert "3 discovered" in out
    assert "2 resolved" in out
    assert "Shares:" in out
    assert "3 discovered" in out
    assert "Directories:" in out
    assert "2 walked" in out
    assert "Files:" in out
    assert "2 checked" in out
    # Finding counts
    assert "Black: 2" in out
    assert "Red: 1" in out
    assert "Yellow: 1" in out
    assert "Green: 1" in out
    # Individual findings
    assert "[Black] [KeepPassKDBX]" in out
    assert "[Red] [WebConfig]" in out
    assert "passwords.kdbx" in out
    # Context shown
    assert "BEGIN RSA PRIVATE KEY" in out


def test_json_output(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    _populate_db(conn)
    conn.close()

    result = runner.invoke(app, ["results", "--state", str(db_path), "--format", "json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    # Stats structure
    assert data["stats"]["computers"]["total"] == 3
    assert data["stats"]["computers"]["resolved"] == 2
    assert data["stats"]["shares"]["done"] == 2
    assert data["stats"]["files"]["checked"] == 2
    assert data["stats"]["findings"]["total"] == 5
    assert data["stats"]["findings"]["black"] == 2
    # Findings list
    assert len(data["findings"]) == 5
    assert data["findings"][0]["triage"] == "Black"
    assert data["findings"][-1]["triage"] == "Green"


def test_min_interest_filters(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    _populate_db(conn)
    conn.close()

    # --min-interest 2 → only Red and Black
    result = runner.invoke(
        app, ["results", "--state", str(db_path), "--format", "json", "-b", "2"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data["findings"]) == 3
    triages = {f["triage"] for f in data["findings"]}
    assert triages == {"Black", "Red"}

    # --min-interest 3 → Black only
    result = runner.invoke(
        app, ["results", "--state", str(db_path), "--format", "json", "-b", "3"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data["findings"]) == 2
    assert all(f["triage"] == "Black" for f in data["findings"])


def test_missing_db_error(tmp_path):
    result = runner.invoke(app, ["results", "--state", str(tmp_path / "nope.db")])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_empty_db(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    conn.close()

    result = runner.invoke(app, ["results", "--state", str(db_path), "--no-color"])
    assert result.exit_code == 0
    assert "0 discovered" in result.output
    assert "Findings (0)" in result.output


def test_wal_uncheckpointed_findings_visible(tmp_path):
    """Findings committed in WAL mode but not checkpointed must be visible.

    Reproduces the Ctrl+C scenario: a subprocess writes findings in WAL mode
    then is killed with SIGKILL (no clean close → no checkpoint).  The -wal
    file is left on disk with committed data.  ``snaffler results`` must
    recover and display those findings.
    """
    db_path = tmp_path / "snaffler.db"

    # Spawn a subprocess that creates the DB, writes a finding, and gets
    # SIGKILL'd before close() can checkpoint the WAL.
    script = textwrap.dedent(f"""\
        import sqlite3, os, signal
        conn = sqlite3.connect("{db_path}")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(\"\"\"
            CREATE TABLE sync (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE target_computer (
                name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT,
                done INTEGER DEFAULT 0);
            CREATE TABLE target_share (
                unc_path TEXT PRIMARY KEY COLLATE NOCASE,
                done INTEGER DEFAULT 0);
            CREATE TABLE target_dir (
                unc_path TEXT PRIMARY KEY COLLATE NOCASE,
                share TEXT NOT NULL COLLATE NOCASE,
                walked INTEGER DEFAULT 0);
            CREATE TABLE target_file (
                unc_path TEXT PRIMARY KEY COLLATE NOCASE,
                share TEXT NOT NULL COLLATE NOCASE,
                size INTEGER, mtime REAL,
                checked INTEGER DEFAULT 0);
            CREATE TABLE finding (
                finding_id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL, triage TEXT NOT NULL,
                rule_name TEXT NOT NULL, match_text TEXT,
                context TEXT, size INTEGER, mtime TEXT,
                found_at TEXT NOT NULL);
        \"\"\")
        conn.execute(
            "INSERT INTO finding VALUES (?,?,?,?,?,?,?,?,?)",
            ("wal1", "//DC01/IT$/passwords.kdbx", "Black", "KeepPassKDBX",
             None, None, 2200000, "2025-01-15", "2026-02-24T10:30:00"),
        )
        conn.commit()
        os.kill(os.getpid(), signal.SIGKILL)
    """)
    subprocess.run([sys.executable, "-c", script])

    # Verify the WAL file exists (uncheckpointed data)
    wal_file = db_path.parent / (db_path.name + "-wal")
    assert wal_file.exists(), "WAL file should exist with uncheckpointed data"

    # snaffler results must see the Black finding
    result = runner.invoke(
        app, ["results", "--state", str(db_path), "--format", "json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["stats"]["findings"]["black"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["triage"] == "Black"


def test_empty_db_json(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    conn.close()

    result = runner.invoke(app, ["results", "--state", str(db_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["stats"]["findings"]["total"] == 0
    assert data["findings"] == []


# ---------- rules subcommand ----------


def test_rules_subcommand_shows_all(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    _populate_db(conn)
    conn.close()

    result = runner.invoke(app, ["results", "--state", str(db_path), "--no-color", "rules"])
    assert result.exit_code == 0
    out = result.output
    assert "5 rules" in out
    assert "5 findings" in out
    assert "KeepPassKDBX" in out
    assert "MildlyInteresting" in out


def test_rules_subcommand_min_interest_filters(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    _populate_db(conn)
    conn.close()

    # --min-interest 3 → Black only
    result = runner.invoke(
        app, ["results", "--state", str(db_path), "--no-color", "-b", "3", "rules"]
    )
    assert result.exit_code == 0
    out = result.output
    assert "2 rules" in out
    assert "2 findings" in out
    assert "[Black]" in out
    assert "[Red]" not in out
    assert "[Yellow]" not in out
    assert "[Green]" not in out

    # --min-interest 2 → Red + Black
    result = runner.invoke(
        app, ["results", "--state", str(db_path), "--no-color", "-b", "2", "rules"]
    )
    assert result.exit_code == 0
    out = result.output
    assert "[Red]" in out
    assert "[Black]" in out
    assert "[Yellow]" not in out
    assert "[Green]" not in out


def test_rules_subcommand_json(tmp_path):
    db_path = tmp_path / "snaffler.db"
    conn = _create_db(db_path)
    _populate_db(conn)
    conn.close()

    result = runner.invoke(
        app, ["results", "--state", str(db_path), "-b", "3", "rules", "--format", "json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 2
    assert all(r["triage"] == "Black" for r in data)
