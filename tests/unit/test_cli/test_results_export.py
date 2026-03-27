"""Tests for snaffler results export/import subcommands."""

import gzip
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from snaffler.cli.main import app

runner = CliRunner()


def _open_exported_db(gz_path):
    """Decompress a gzip-exported DB and return an open sqlite3 connection.

    Returns (connection, tmp_path) — caller must close conn and delete tmp_path.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp_path = tmp.name
    tmp.close()
    with gzip.open(str(gz_path), "rb") as f_in, open(tmp_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    return sqlite3.connect(tmp_path), tmp_path


def _load_exported_json(gz_path):
    """Load a gzip-exported JSON file and return the parsed data."""
    with gzip.open(str(gz_path), "rt", encoding="utf-8") as f:
        return json.load(f)


# ---------- helpers ----------


def _create_db(path, *, readable_column=True):
    """Create a minimal scan DB with schema matching SQLiteStateStore."""
    conn = sqlite3.connect(str(path))
    readable_col = "readable INTEGER DEFAULT NULL," if readable_column else ""
    conn.executescript(f"""
        CREATE TABLE sync (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE target_computer (
            name TEXT PRIMARY KEY COLLATE NOCASE,
            ip TEXT,
            done INTEGER DEFAULT 0
        );
        CREATE TABLE target_share (
            unc_path TEXT PRIMARY KEY COLLATE NOCASE,
            {readable_col}
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
        "INSERT INTO target_share (unc_path, readable, done) VALUES (?, ?, ?)",
        [
            ("//DC01/SYSVOL", 1, 1),
            ("//DC01/NETLOGON", 1, 1),
            ("//FS01/Data", 0, 0),
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


# ───────────────────────────── DB Export ─────────────────────────────


class TestExportDB:
    def test_export_db_creates_valid_sqlite(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.db"
        result = runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        assert result.exit_code == 0
        assert "Exported state DB to" in result.output

        # Verify the exported file is gzip-compressed valid SQLite
        exp_conn, tmp_db = _open_exported_db(out_path)
        try:
            findings = exp_conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
            computers = exp_conn.execute("SELECT COUNT(*) FROM target_computer").fetchone()[0]
            shares = exp_conn.execute("SELECT COUNT(*) FROM target_share").fetchone()[0]
        finally:
            exp_conn.close()
            Path(tmp_db).unlink(missing_ok=True)

        assert findings == 5
        assert computers == 3
        assert shares == 3

    def test_export_db_is_gzip(self, tmp_path):
        """Exported DB should be gzip compressed."""
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.db"
        runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        # Check gzip magic bytes
        with open(out_path, "rb") as f:
            assert f.read(2) == b"\x1f\x8b"

    def test_export_db_preserves_data_integrity(self, tmp_path):
        """All finding data should be preserved exactly."""
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.db"
        runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        exp_conn, tmp_db = _open_exported_db(out_path)
        try:
            row = exp_conn.execute(
                "SELECT file_path, triage, rule_name, context FROM finding WHERE finding_id = 'bbb'"
            ).fetchone()
        finally:
            exp_conn.close()
            Path(tmp_db).unlink(missing_ok=True)

        assert row[0] == "//FS02/deploy$/id_rsa"
        assert row[1] == "Black"
        assert row[2] == "PrivateKey"
        assert row[3] == "-----BEGIN RSA PRIVATE KEY-----"

    def test_export_db_explicit_format(self, tmp_path):
        """--format db should work even with a non-.db extension."""
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.sqlite"
        result = runner.invoke(
            app,
            ["results", "export", str(out_path), "--state-file", str(db_path), "--format", "db"],
        )

        assert result.exit_code == 0
        exp_conn, tmp_db = _open_exported_db(out_path)
        try:
            count = exp_conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
        finally:
            exp_conn.close()
            Path(tmp_db).unlink(missing_ok=True)
        assert count == 5


# ───────────────────────────── JSON Export ─────────────────────────────


class TestExportJSON:
    def test_export_json_produces_valid_json(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.json"
        result = runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        assert result.exit_code == 0
        assert "Exported 5 findings to" in result.output

        data = _load_exported_json(out_path)

        assert "stats" in data
        assert "findings" in data

    def test_export_json_correct_structure(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.json"
        runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        data = _load_exported_json(out_path)

        # Check stats
        stats = data["stats"]
        assert stats["computers"] == 3
        assert stats["shares"] == 3
        assert stats["files_scanned"] == 2
        assert stats["findings"] == 5

        # Check findings
        findings = data["findings"]
        assert len(findings) == 5

        # All findings should have required keys
        for finding in findings:
            assert "id" in finding
            assert "file_path" in finding
            assert "triage" in finding
            assert "rule_name" in finding
            assert "found_at" in finding

    def test_export_json_finding_values(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.json"
        runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        data = _load_exported_json(out_path)

        # Find the PrivateKey finding
        pk = [f for f in data["findings"] if f["id"] == "bbb"][0]
        assert pk["file_path"] == "//FS02/deploy$/id_rsa"
        assert pk["triage"] == "Black"
        assert pk["rule_name"] == "PrivateKey"
        assert pk["context"] == "-----BEGIN RSA PRIVATE KEY-----"
        assert pk["size"] == 1700

    def test_export_json_explicit_format(self, tmp_path):
        """--format json should work even with a non-.json extension."""
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        out_path = tmp_path / "exported.txt"
        result = runner.invoke(
            app,
            ["results", "export", str(out_path), "--state-file", str(db_path), "--format", "json"],
        )

        assert result.exit_code == 0
        data = _load_exported_json(out_path)
        assert len(data["findings"]) == 5

    def test_export_json_empty_db(self, tmp_path):
        """Export of an empty DB should produce valid JSON with zero findings."""
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        conn.close()

        out_path = tmp_path / "exported.json"
        result = runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        assert result.exit_code == 0
        data = _load_exported_json(out_path)
        assert data["stats"]["findings"] == 0
        assert data["findings"] == []


# ───────────────────────────── Format Detection ─────────────────────────────


class TestFormatDetection:
    def test_db_extension_auto_detected(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        conn.close()

        out_path = tmp_path / "exported.db"
        result = runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        assert result.exit_code == 0
        assert "Exported state DB to" in result.output

    def test_json_extension_auto_detected(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        conn.close()

        out_path = tmp_path / "exported.json"
        result = runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        assert result.exit_code == 0
        assert "findings to" in result.output

    def test_unknown_extension_errors(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        conn.close()

        out_path = tmp_path / "exported.xyz"
        result = runner.invoke(
            app, ["results", "export", str(out_path), "--state-file", str(db_path)]
        )

        assert result.exit_code != 0
        assert "cannot detect format" in result.output

    def test_explicit_format_overrides_extension(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        _populate_db(conn)
        conn.close()

        # .db extension but --format json
        out_path = tmp_path / "results.db"
        result = runner.invoke(
            app,
            ["results", "export", str(out_path), "--state-file", str(db_path), "--format", "json"],
        )

        assert result.exit_code == 0
        data = _load_exported_json(out_path)
        assert "findings" in data

    def test_unsupported_format_errors(self, tmp_path):
        db_path = tmp_path / "snaffler.db"
        conn = _create_db(db_path)
        conn.close()

        out_path = tmp_path / "exported.csv"
        result = runner.invoke(
            app,
            ["results", "export", str(out_path), "--state-file", str(db_path), "--format", "csv"],
        )

        assert result.exit_code != 0
        assert "unsupported format" in result.output


# ───────────────────────────── Error Handling ─────────────────────────────


class TestExportErrors:
    def test_export_nonexistent_state_file(self, tmp_path):
        out_path = tmp_path / "exported.db"
        result = runner.invoke(
            app,
            ["results", "export", str(out_path), "--state-file", str(tmp_path / "no_such.db")],
        )

        assert result.exit_code != 0
        assert "not found" in result.output


# ───────────────────────────── DB Import ─────────────────────────────


class TestImportDB:
    def test_import_db_merges_findings(self, tmp_path):
        # Create source DB with findings
        src_path = tmp_path / "source.db"
        src_conn = _create_db(src_path)
        _populate_db(src_conn)
        src_conn.close()

        # Create target DB (empty)
        tgt_path = tmp_path / "target.db"
        tgt_conn = _create_db(tgt_path)
        tgt_conn.close()

        result = runner.invoke(
            app,
            ["results", "import", str(src_path), "--state-file", str(tgt_path)],
        )

        assert result.exit_code == 0
        assert "Imported 5 new findings" in result.output

        # Verify findings exist in target
        conn = sqlite3.connect(str(tgt_path))
        count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
        conn.close()
        assert count == 5

    def test_import_db_deduplicates_findings(self, tmp_path):
        """Duplicate finding_ids should be skipped."""
        src_path = tmp_path / "source.db"
        src_conn = _create_db(src_path)
        _populate_db(src_conn)
        src_conn.close()

        # Create target with one overlapping finding
        tgt_path = tmp_path / "target.db"
        tgt_conn = _create_db(tgt_path)
        tgt_conn.execute(
            "INSERT INTO finding (finding_id, file_path, triage, rule_name, found_at) "
            "VALUES ('aaa', '//DC01/IT$/passwords.kdbx', 'Black', 'KeepPassKDBX', '2026-01-01T00:00:00')"
        )
        tgt_conn.commit()
        tgt_conn.close()

        result = runner.invoke(
            app,
            ["results", "import", str(src_path), "--state-file", str(tgt_path)],
        )

        assert result.exit_code == 0
        assert "Imported 4 new findings" in result.output

        # Total should be 5 (1 existing + 4 new), not 6
        conn = sqlite3.connect(str(tgt_path))
        count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
        conn.close()
        assert count == 5

    def test_import_db_merges_computers_and_shares(self, tmp_path):
        src_path = tmp_path / "source.db"
        src_conn = _create_db(src_path)
        _populate_db(src_conn)
        src_conn.close()

        tgt_path = tmp_path / "target.db"
        tgt_conn = _create_db(tgt_path)
        tgt_conn.close()

        runner.invoke(
            app,
            ["results", "import", str(src_path), "--state-file", str(tgt_path)],
        )

        conn = sqlite3.connect(str(tgt_path))
        computers = conn.execute("SELECT COUNT(*) FROM target_computer").fetchone()[0]
        shares = conn.execute("SELECT COUNT(*) FROM target_share").fetchone()[0]
        conn.close()

        assert computers == 3
        assert shares == 3

    def test_import_into_nonexistent_db_creates_it(self, tmp_path):
        """Importing into a non-existent state file should create it."""
        src_path = tmp_path / "source.db"
        src_conn = _create_db(src_path)
        _populate_db(src_conn)
        src_conn.close()

        tgt_path = tmp_path / "new_target.db"
        assert not tgt_path.exists()

        result = runner.invoke(
            app,
            ["results", "import", str(src_path), "--state-file", str(tgt_path)],
        )

        assert result.exit_code == 0
        assert tgt_path.exists()

        conn = sqlite3.connect(str(tgt_path))
        count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
        conn.close()
        assert count == 5


# ───────────────────────────── JSON Import ─────────────────────────────


class TestImportJSON:
    def test_import_json_findings(self, tmp_path):
        # Create a JSON export
        data = {
            "stats": {"computers": 1, "shares": 1, "files_scanned": 10, "findings": 2},
            "findings": [
                {
                    "id": "f001",
                    "file_path": "//SRV/share/secret.txt",
                    "triage": "Red",
                    "rule_name": "SecretFile",
                    "match": "password=",
                    "context": "password=hunter2",
                    "size": 100,
                    "mtime": "2025-06-01",
                    "found_at": "2026-03-01T12:00:00",
                },
                {
                    "id": "f002",
                    "file_path": "//SRV/share/config.xml",
                    "triage": "Yellow",
                    "rule_name": "ConfigFile",
                    "match": None,
                    "context": None,
                    "size": 500,
                    "mtime": "2025-07-01",
                    "found_at": "2026-03-01T12:01:00",
                },
            ],
        }
        json_path = tmp_path / "export.json"
        with open(json_path, "w") as f:
            json.dump(data, f)

        tgt_path = tmp_path / "target.db"

        result = runner.invoke(
            app,
            ["results", "import", str(json_path), "--state-file", str(tgt_path)],
        )

        assert result.exit_code == 0
        assert "Imported 2 new findings" in result.output

        conn = sqlite3.connect(str(tgt_path))
        rows = conn.execute(
            "SELECT finding_id, file_path, triage, rule_name FROM finding ORDER BY finding_id"
        ).fetchall()
        conn.close()

        assert len(rows) == 2
        assert rows[0][0] == "f001"
        assert rows[0][2] == "Red"
        assert rows[1][0] == "f002"
        assert rows[1][2] == "Yellow"

    def test_import_json_deduplicates(self, tmp_path):
        data = {
            "findings": [
                {
                    "id": "dup01",
                    "file_path": "//SRV/share/file.txt",
                    "triage": "Green",
                    "rule_name": "TestRule",
                    "found_at": "2026-03-01T12:00:00",
                },
            ],
        }
        json_path = tmp_path / "export.json"
        with open(json_path, "w") as f:
            json.dump(data, f)

        tgt_path = tmp_path / "target.db"
        # First import
        result1 = runner.invoke(app, ["results", "import", str(json_path), "--state-file", str(tgt_path)])
        assert "Imported 1 new findings" in result1.output

        # Second import of same data — should report 0 new
        result = runner.invoke(
            app, ["results", "import", str(json_path), "--state-file", str(tgt_path)]
        )

        assert result.exit_code == 0
        assert "Imported 0 new findings" in result.output

        conn = sqlite3.connect(str(tgt_path))
        count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
        conn.close()
        assert count == 1  # no duplicates


# ───────────────────────────── Import Errors ─────────────────────────────


class TestImportErrors:
    def test_import_nonexistent_input(self, tmp_path):
        result = runner.invoke(
            app,
            ["results", "import", str(tmp_path / "no_such.db"), "--state-file", str(tmp_path / "target.db")],
        )

        assert result.exit_code != 0
        assert "not found" in result.output


# ───────────────────────────── Round-trip ─────────────────────────────


class TestRoundTrip:
    def test_export_db_then_import(self, tmp_path):
        """Export as DB, then import into a fresh DB — all findings preserved."""
        src_path = tmp_path / "source.db"
        src_conn = _create_db(src_path)
        _populate_db(src_conn)
        src_conn.close()

        exported_path = tmp_path / "exported.db"
        runner.invoke(
            app, ["results", "export", str(exported_path), "--state-file", str(src_path)]
        )

        tgt_path = tmp_path / "fresh.db"
        result = runner.invoke(
            app, ["results", "import", str(exported_path), "--state-file", str(tgt_path)]
        )

        assert result.exit_code == 0
        conn = sqlite3.connect(str(tgt_path))
        count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
        conn.close()
        assert count == 5

    def test_export_json_then_import(self, tmp_path):
        """Export as JSON, then import into a fresh DB — all findings preserved."""
        src_path = tmp_path / "source.db"
        src_conn = _create_db(src_path)
        _populate_db(src_conn)
        src_conn.close()

        json_path = tmp_path / "exported.json"
        runner.invoke(
            app, ["results", "export", str(json_path), "--state-file", str(src_path)]
        )

        tgt_path = tmp_path / "fresh.db"
        result = runner.invoke(
            app, ["results", "import", str(json_path), "--state-file", str(tgt_path)]
        )

        assert result.exit_code == 0
        conn = sqlite3.connect(str(tgt_path))
        count = conn.execute("SELECT COUNT(*) FROM finding").fetchone()[0]
        conn.close()
        assert count == 5
