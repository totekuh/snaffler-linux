"""
Integration test: FTP snaffling against a real in-process FTP server.

Uses pyftpdlib to serve tests/data/ over FTP, then runs:
  1. SnafflerRunner (full pipeline) — anonymous + authenticated
  2. Snaffler library API with injected FTP walker/reader
  3. Subpath scanning (start from a subdirectory, not root)
  4. Resume across two runs
  5. --exclude-path, --match, --max-depth, --min-interest flags

No mocking — real FTP server, real rules, real classification engine.
"""

import logging
import socket
import tempfile
import threading
from pathlib import Path

import pytest

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)

pyftpdlib = pytest.importorskip("pyftpdlib")

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from snaffler import Snaffler
from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.loader import RuleLoader
from snaffler.classifiers.rules import Triage
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.ftp_tree_walker import FTPTreeWalker
from snaffler.engine.runner import SnafflerRunner
from snaffler.resume.scan_state import SQLiteStateStore
from snaffler.utils.logger import set_finding_store

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# ---------------------------------------------------------------------------
# FTP server fixtures
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_ftp_server(root, port, username=None, password=None):
    """Start an FTP server in a daemon thread. Returns (server, thread).

    Creates a fresh handler subclass per server to avoid class-level
    authorizer conflicts when multiple FTP servers run concurrently.
    """
    authorizer = DummyAuthorizer()
    if username:
        authorizer.add_user(username, password, str(root), perm="elr")
    else:
        authorizer.add_anonymous(str(root), perm="elr")

    # Each server gets its own handler class — FTPHandler uses class-level
    # state (authorizer, passive_ports) that would conflict otherwise.
    handler = type("_FTPHandler", (FTPHandler,), {
        "authorizer": authorizer,
        "passive_ports": range(60000, 60100),
        "banner": "test-ftp-server",
    })

    server = FTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture()
def anon_ftp():
    """Anonymous FTP server serving tests/data/."""
    port = _free_port()
    server, thread = _start_ftp_server(_DATA_DIR, port)
    yield port
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        server.close_all()


@pytest.fixture()
def auth_ftp():
    """Authenticated FTP server (testuser/testpass) serving tests/data/."""
    port = _free_port()
    server, thread = _start_ftp_server(
        _DATA_DIR, port, username="ftpuser", password="ftppass",
    )
    yield port
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        server.close_all()


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg(port, subpath="/", username="", password=""):
    """Build SnafflerConfiguration targeting an FTP server."""
    url = f"ftp://127.0.0.1:{port}{subpath}"
    c = SnafflerConfiguration()
    c.targets.ftp_targets = [url]
    c.targets.ftp_tls = False
    c.auth.username = username
    c.auth.password = password
    c.auth.smb_timeout = 10
    c.scanning.max_read_bytes = 2 * 1024 * 1024
    c.scanning.max_file_bytes = 10 * 1024 * 1024
    c.scanning.match_context_bytes = 200
    c.scanning.min_interest = 0
    c.advanced.share_threads = 2
    c.advanced.tree_threads = 4
    c.advanced.file_threads = 4
    c.state.state_db = ":memory:"
    RuleLoader.load(c)
    return c


def _run(cfg):
    """Execute SnafflerRunner and return (runner, progress)."""
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress


# ---------------------------------------------------------------------------
# Runner: anonymous FTP
# ---------------------------------------------------------------------------

class TestRunnerAnonymous:

    def test_produces_findings(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_scans_more_than_matches(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)
        assert p.files_scanned > p.files_matched

    def test_severity_counts_sum(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_finds_black_severity(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)
        assert p.severity_black > 0

    def test_finds_red_severity(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)
        assert p.severity_red > 0

    def test_scan_complete_flag(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)
        assert p.scan_complete is True

    def test_shares_found_equals_targets(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)
        assert p.shares_found == 1

    def test_findings_logged(self, anon_ftp, caplog):
        cfg = _make_cfg(anon_ftp)
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            _run(cfg)
        findings = [r for r in caplog.records if "[Red]" in r.message or "[Black]" in r.message]
        assert len(findings) > 0

    def test_finding_paths_are_ftp_urls(self, anon_ftp, caplog):
        """Finding paths in log output should be ftp:// URLs."""
        cfg = _make_cfg(anon_ftp)
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            _run(cfg)
        ftp_findings = [
            r for r in caplog.records
            if hasattr(r, "file_path") and r.file_path.startswith("ftp://")
        ]
        assert len(ftp_findings) > 0


# ---------------------------------------------------------------------------
# Runner: authenticated FTP
# ---------------------------------------------------------------------------

class TestRunnerAuthenticated:

    def test_produces_findings_with_creds(self, auth_ftp):
        cfg = _make_cfg(auth_ftp, username="ftpuser", password="ftppass")
        _, p = _run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_severity_counts_match(self, auth_ftp):
        cfg = _make_cfg(auth_ftp, username="ftpuser", password="ftppass")
        _, p = _run(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_wrong_creds_no_findings(self, auth_ftp):
        """Wrong credentials should produce zero findings (connection fails)."""
        cfg = _make_cfg(auth_ftp, username="wrong", password="wrong")
        _, p = _run(cfg)
        assert p.files_scanned == 0

    def test_anonymous_rejected(self, auth_ftp):
        """Anonymous access to an authenticated server should produce zero findings."""
        cfg = _make_cfg(auth_ftp)
        _, p = _run(cfg)
        assert p.files_scanned == 0

    def test_consistent_results_across_runs(self, auth_ftp):
        """Two authenticated scans of same data should find the same findings."""
        cfg1 = _make_cfg(auth_ftp, username="ftpuser", password="ftppass")
        _, p1 = _run(cfg1)

        cfg2 = _make_cfg(auth_ftp, username="ftpuser", password="ftppass")
        _, p2 = _run(cfg2)

        assert p1.files_matched == p2.files_matched
        assert p1.severity_black == p2.severity_black
        assert p1.severity_red == p2.severity_red


# ---------------------------------------------------------------------------
# Runner: subpath scanning
# ---------------------------------------------------------------------------

class TestRunnerSubpath:

    def test_subpath_scans_only_subtree(self, anon_ftp):
        """Scanning from /home should only find files under /home."""
        cfg = _make_cfg(anon_ftp, subpath="/home")
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        cfg.state.state_db = db_path

        try:
            _run(cfg)
            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            assert len(findings) > 0
            for f in findings:
                assert "/home/" in f["file_path"], f"Finding outside /home: {f['file_path']}"
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_subpath_fewer_findings_than_root(self, anon_ftp):
        """Scanning a subpath should find fewer files than scanning root."""
        cfg_root = _make_cfg(anon_ftp)
        _, p_root = _run(cfg_root)

        cfg_sub = _make_cfg(anon_ftp, subpath="/home")
        _, p_sub = _run(cfg_sub)

        assert p_sub.files_scanned < p_root.files_scanned

    def test_deep_subpath(self, anon_ftp):
        """Scanning a deep subpath like /home/user/.ssh should still work."""
        cfg = _make_cfg(anon_ftp, subpath="/home/user/.ssh")
        _, p = _run(cfg)
        # .ssh dir has at least custom_key
        assert p.files_scanned >= 1


# ---------------------------------------------------------------------------
# Runner: flags
# ---------------------------------------------------------------------------

class TestRunnerFlags:

    def test_exclude_path(self, anon_ftp):
        """--exclude-path should skip matching directories."""
        cfg = _make_cfg(anon_ftp)
        _, p_full = _run(cfg)

        cfg_excl = _make_cfg(anon_ftp)
        cfg_excl.targets.exclude_unc = ["*/home/*"]
        _, p_excl = _run(cfg_excl)

        assert p_excl.files_scanned < p_full.files_scanned

    def test_min_interest_filters(self, anon_ftp):
        """--min-interest 2 should only report Red and Black."""
        cfg = _make_cfg(anon_ftp)
        cfg.scanning.min_interest = 2
        _, p = _run(cfg)
        assert p.severity_green == 0
        assert p.severity_yellow == 0
        assert p.files_matched > 0

    def test_max_depth_zero(self, anon_ftp):
        """--max-depth 0 scans only the root directory (no subdirs)."""
        cfg = _make_cfg(anon_ftp)
        cfg.scanning.max_depth = 0
        _, p = _run(cfg)
        # Root has files, but far fewer than full recursive scan
        cfg_full = _make_cfg(anon_ftp)
        _, p_full = _run(cfg_full)
        assert p.files_scanned < p_full.files_scanned

    def test_match_filter(self, anon_ftp):
        """--match regex should only report findings matching the pattern."""
        cfg = _make_cfg(anon_ftp)
        cfg.scanning.match_filter = r"\.pem"
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        cfg.state.state_db = db_path

        try:
            _run(cfg)
            store = SQLiteStateStore(db_path)
            findings = store.load_findings()
            store.close()

            assert len(findings) > 0
            for f in findings:
                assert ".pem" in f["file_path"].lower(), f"Non-pem finding: {f['file_path']}"
        finally:
            Path(db_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Runner: resume
# ---------------------------------------------------------------------------

class TestRunnerResume:

    def test_resume_no_new_findings(self, anon_ftp):
        """Second run with same DB should not produce new findings."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = _make_cfg(anon_ftp)
            cfg.state.state_db = db_path
            _run(cfg)

            store = SQLiteStateStore(db_path)
            count1 = store.count_findings()
            store.close()

            cfg2 = _make_cfg(anon_ftp)
            cfg2.state.state_db = db_path
            _run(cfg2)

            store = SQLiteStateStore(db_path)
            count2 = store.count_findings()
            store.close()

            assert count1 > 0
            assert count2 == count1
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_resume_restores_finding_counts(self, anon_ftp):
        """On resume, progress should reflect findings from previous run."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg = _make_cfg(anon_ftp)
            cfg.state.state_db = db_path
            _, p1 = _run(cfg)

            cfg2 = _make_cfg(anon_ftp)
            cfg2.state.state_db = db_path
            _, p2 = _run(cfg2)

            # Progress should show findings from DB even though no new scan happened
            assert p2.files_matched >= p1.files_matched
        finally:
            Path(db_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Library API with FTP transport
# ---------------------------------------------------------------------------

class TestLibraryAPI:

    def test_walk_produces_findings(self, anon_ftp):
        """Snaffler.walk() with FTP walker/reader produces findings."""
        cfg = _make_cfg(anon_ftp)
        walker = FTPTreeWalker(cfg)
        reader = FTPFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{anon_ftp}"))

        assert len(findings) > 0
        assert all(isinstance(f, FileResult) for f in findings)

    def test_walk_paths_are_ftp_urls(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        walker = FTPTreeWalker(cfg)
        reader = FTPFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{anon_ftp}"))

        for f in findings:
            base = f.file_path.split("\u2192")[0]  # strip archive member
            assert base.startswith("ftp://"), f"Non-FTP path: {f.file_path}"

    def test_walk_subpath(self, anon_ftp):
        """walk() starting from a subpath only finds files under that path."""
        cfg = _make_cfg(anon_ftp, subpath="/home")
        walker = FTPTreeWalker(cfg)
        reader = FTPFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{anon_ftp}/home"))

        assert len(findings) > 0
        for f in findings:
            base = f.file_path.split("\u2192")[0]
            assert "/home/" in base, f"Finding outside /home: {f.file_path}"

    def test_walk_with_auth(self, auth_ftp):
        cfg = _make_cfg(auth_ftp, username="ftpuser", password="ftppass")
        walker = FTPTreeWalker(cfg)
        reader = FTPFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{auth_ftp}"))

        assert len(findings) > 0

    def test_walk_severity_distribution(self, anon_ftp):
        cfg = _make_cfg(anon_ftp)
        walker = FTPTreeWalker(cfg)
        reader = FTPFileAccessor(cfg)

        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{anon_ftp}"))

        black = [f for f in findings if f.triage == Triage.BLACK]
        red = [f for f in findings if f.triage == Triage.RED]
        assert len(black) > 0
        assert len(red) > 0

    def test_walk_matches_runner_count(self, anon_ftp):
        """Library API and runner should find the same number of findings."""
        # Runner
        cfg = _make_cfg(anon_ftp)
        _, p = _run(cfg)

        # API
        cfg2 = _make_cfg(anon_ftp)
        walker = FTPTreeWalker(cfg2)
        reader = FTPFileAccessor(cfg2)
        s = Snaffler(walker=walker, reader=reader)
        findings = list(s.walk(f"ftp://127.0.0.1:{anon_ftp}"))

        assert len(findings) == p.files_matched

    def test_check_file_two_phase(self, anon_ftp):
        """Two-phase API (check_file + scan_content) works with FTP data."""
        from snaffler.api import FileCheckStatus

        cfg = _make_cfg(anon_ftp)
        reader = FTPFileAccessor(cfg)
        s = Snaffler(reader=reader)

        # Read a known credential file via FTP
        data = reader.read(f"ftp://127.0.0.1:{anon_ftp}/secrets.txt")
        assert data is not None

        check = s.check_file("secrets.txt", size=len(data), mtime_epoch=0)
        if check.status == FileCheckStatus.NEEDS_CONTENT:
            result = s.scan_content(data, prior=check)
            assert result is not None
        elif check.status == FileCheckStatus.FINDING:
            assert check.result is not None
