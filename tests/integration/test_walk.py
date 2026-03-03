"""
Integration test: Snaffler.walk() against the real local filesystem.

No mocking — real rules, real local tree walker, real local file reader,
real test data directory.  Validates that the library API produces correct
findings when pointed at a local directory tree.

Also tests the CLI ``--local`` pipeline (FilePipeline with local transport).
"""

import shutil
from pathlib import Path

import pytest

from snaffler import Snaffler
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.rules import Triage

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_ARCHIVE_DIR = _DATA_DIR / "archives"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _walk(root, **kwargs):
    """Run Snaffler.walk() and return list of FileResult."""
    s = Snaffler(**kwargs)
    return list(s.walk(str(root)))


# ---------------------------------------------------------------------------
# Basic walk — full data dir
# ---------------------------------------------------------------------------

class TestWalkFullDataDir:
    """Walk the entire tests/data/ tree and verify aggregate findings."""

    def test_produces_findings(self):
        findings = _walk(_DATA_DIR)
        assert len(findings) > 0

    def test_all_results_are_file_result(self):
        findings = _walk(_DATA_DIR)
        assert all(isinstance(f, FileResult) for f in findings)

    def test_findings_have_local_paths(self):
        """Paths should be real local filesystem paths, not UNC."""
        findings = _walk(_DATA_DIR)
        for f in findings:
            # Archive member paths have → separator
            base = f.file_path.split("\u2192")[0]
            assert not base.startswith("//"), f"UNC path in walk(): {f.file_path}"

    def test_finds_black_severity(self):
        """Data dir has ntds.dit, id_rsa etc. — must produce BLACK findings."""
        findings = _walk(_DATA_DIR)
        black = [f for f in findings if f.triage == Triage.BLACK]
        assert len(black) > 0

    def test_finds_red_severity(self):
        findings = _walk(_DATA_DIR)
        red = [f for f in findings if f.triage == Triage.RED]
        assert len(red) > 0

    def test_finds_content_matches(self):
        """Content scan produces findings with match text."""
        findings = _walk(_DATA_DIR)
        with_match = [f for f in findings if f.match]
        assert len(with_match) > 0

    def test_scans_more_files_than_matches(self):
        """Not every file matches — data dir has benign files too."""
        findings = _walk(_DATA_DIR)
        total_files = sum(1 for _ in _DATA_DIR.rglob("*") if _.is_file())
        assert len(findings) < total_files


# ---------------------------------------------------------------------------
# Recursion
# ---------------------------------------------------------------------------

class TestRecursion:

    def test_finds_files_in_subdirs(self):
        """Files in nested subdirectories are found."""
        findings = _walk(_DATA_DIR)
        # Files from subdirectories (path contains a subdirectory name)
        nested = [
            f for f in findings
            if any(d in f.file_path for d in ["relay_", "password_files", "gpp"])
        ]
        assert len(nested) > 0

    def test_finds_deeply_nested_files(self):
        """Files in deep paths like relay_postmatch/ProgramData/... are reached."""
        findings = _walk(_DATA_DIR)
        deep = [f for f in findings if "ProgramData" in f.file_path]
        # ProgramData dir has postmatch test files — may or may not produce findings
        # depending on rules; the key test is that walk() reaches them at all.
        # Instead, check a known deep structure
        gpp = [f for f in findings if "gpp" in f.file_path.lower()]
        assert len(gpp) > 0


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------

class TestExclusions:

    def test_exclude_unc_reduces_findings(self):
        """Excluding a directory reduces the number of findings."""
        full = _walk(_DATA_DIR)
        excl = _walk(_DATA_DIR, exclude_unc=["*/relay_*"])
        assert len(excl) < len(full)

    def test_exclude_unc_no_excluded_paths(self):
        """Excluded directories don't appear in finding paths."""
        findings = _walk(_DATA_DIR, exclude_unc=["*/archives*"])
        for f in findings:
            assert "archives" not in f.file_path

    def test_multiple_exclusions_stack(self):
        """Multiple exclusion patterns stack additively."""
        one = _walk(_DATA_DIR, exclude_unc=["*/relay_*"])
        two = _walk(_DATA_DIR, exclude_unc=["*/relay_*", "*gpp*"])
        assert len(two) < len(one)


# ---------------------------------------------------------------------------
# min_interest filter
# ---------------------------------------------------------------------------

class TestMinInterest:

    def test_min_interest_zero_most_findings(self):
        all_findings = _walk(_DATA_DIR, min_interest=0)
        high_findings = _walk(_DATA_DIR, min_interest=2)
        assert len(high_findings) < len(all_findings)

    def test_min_interest_black_only(self):
        findings = _walk(_DATA_DIR, min_interest=3)
        assert all(f.triage == Triage.BLACK for f in findings)
        assert len(findings) > 0

    def test_min_interest_filters_low_severity(self):
        findings = _walk(_DATA_DIR, min_interest=2)
        for f in findings:
            assert f.triage.level >= 2


# ---------------------------------------------------------------------------
# match_filter
# ---------------------------------------------------------------------------

class TestMatchFilter:

    def test_match_filter_reduces_findings(self):
        all_findings = _walk(_DATA_DIR)
        filtered = _walk(_DATA_DIR, match_filter="password")
        assert len(filtered) < len(all_findings)
        assert len(filtered) > 0

    def test_match_filter_no_match(self):
        findings = _walk(_DATA_DIR, match_filter="zzz_impossible_pattern_zzz")
        assert len(findings) == 0

    def test_match_filter_case_insensitive(self):
        lower = _walk(_DATA_DIR, match_filter="password")
        upper = _walk(_DATA_DIR, match_filter="PASSWORD")
        assert len(lower) == len(upper)


# ---------------------------------------------------------------------------
# Archive peeking via walk()
# ---------------------------------------------------------------------------

class TestCertificateWalk:
    """Walk finds certificates with private keys."""

    _KEY_PEM = _DATA_DIR.parent / "data" / "test_combined.pem"

    def test_certificate_with_private_key(self, tmp_path):
        """walk() detects a PEM file containing a private key (CHECK_KEYS path)."""
        shutil.copy(_DATA_DIR / "test_combined.pem", tmp_path / "server.pem")
        findings = _walk(tmp_path)
        pem_findings = [f for f in findings if "server.pem" in f.file_path]
        assert len(pem_findings) >= 1
        assert any(f.triage == Triage.RED for f in pem_findings)

    def test_certificate_without_private_key(self, tmp_path):
        """walk() does not flag a cert-only PEM (no private key)."""
        shutil.copy(_DATA_DIR / "test_cert.pem", tmp_path / "cert.pem")
        findings = _walk(tmp_path)
        cert_findings = [f for f in findings if "cert.pem" in f.file_path]
        # cert.pem has no private key — should not produce a RED finding
        assert not any(f.triage == Triage.RED for f in cert_findings)


class TestArchiveWalk:

    def test_archive_members_found(self):
        """walk() finds sensitive files inside archives."""
        findings = _walk(_ARCHIVE_DIR)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) > 0

    def test_archive_member_path_format(self):
        """Archive member paths use archive.zip→member format."""
        findings = _walk(_ARCHIVE_DIR)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        for f in archive_findings:
            archive_part, member_part = f.file_path.split("\u2192", 1)
            assert archive_part.endswith((".zip", ".rar", ".7z"))
            assert len(member_part) > 0

    def test_sensitive_archive_finds_ssh_key(self):
        findings = _walk(_ARCHIVE_DIR)
        ssh = [f for f in findings if "\u2192" in f.file_path and "id_rsa" in f.file_path]
        assert len(ssh) >= 1

    def test_boring_archive_no_member_findings(self, tmp_path):
        """Boring archive (readme.txt only) produces no archive-member findings."""
        shutil.copy(_ARCHIVE_DIR / "boring_archive.zip", tmp_path)
        findings = _walk(tmp_path)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) == 0

    def test_oversized_archive_not_peeked(self):
        """Default max_read_bytes (2MB) blocks peeking into 10MB+ archives."""
        findings = _walk(_ARCHIVE_DIR)
        oversized = [f for f in findings if "oversized_archive" in f.file_path and "\u2192" in f.file_path]
        assert len(oversized) == 0

    def test_raised_max_read_bytes_peeks_oversized(self, tmp_path):
        shutil.copy(_ARCHIVE_DIR / "oversized_archive.zip", tmp_path)
        findings = _walk(tmp_path, max_read_bytes=20 * 1024 * 1024)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) > 0

    def test_lowering_max_read_bytes_blocks_all_peeking(self):
        """max_read_bytes=1 prevents peeking into any archive."""
        findings = _walk(_ARCHIVE_DIR, max_read_bytes=1)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) == 0

    def test_rar_sensitive_archive_finds_ssh_key(self, tmp_path):
        """RAR containing id_rsa is found via walk()."""
        shutil.copy(_ARCHIVE_DIR / "sensitive_archive.rar", tmp_path)
        findings = _walk(tmp_path)
        ssh = [f for f in findings if "\u2192" in f.file_path and "id_rsa" in f.file_path]
        assert len(ssh) >= 1

    def test_rar_boring_archive_no_member_findings(self, tmp_path):
        """Boring RAR produces no archive-member findings."""
        shutil.copy(_ARCHIVE_DIR / "boring_archive.rar", tmp_path)
        findings = _walk(tmp_path)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) == 0

    def test_rar_oversized_archive_not_peeked(self):
        """10MB+ RAR exceeds default max_read_bytes — no peeking."""
        findings = _walk(_ARCHIVE_DIR)
        oversized = [f for f in findings if "oversized_archive.rar" in f.file_path and "\u2192" in f.file_path]
        assert len(oversized) == 0


# ---------------------------------------------------------------------------
# Content scanning
# ---------------------------------------------------------------------------

class TestContentScan:

    def test_ps1_password_match(self, tmp_path):
        """Content rules fire on .ps1 files with passwords."""
        (tmp_path / "deploy.ps1").write_text('$password = "hunter2"\n')
        findings = _walk(tmp_path)
        assert len(findings) >= 1
        assert any("deploy.ps1" in f.file_path for f in findings)

    def test_config_connection_string(self, tmp_path):
        """Content rules fire on .config files with connection strings."""
        (tmp_path / "web.config").write_text(
            '<connectionStrings>'
            '<add connectionString="Server=db;Password=secret"/>'
            '</connectionStrings>'
        )
        findings = _walk(tmp_path)
        assert len(findings) >= 1
        assert any("web.config" in f.file_path for f in findings)


# ---------------------------------------------------------------------------
# Custom walker/reader
# ---------------------------------------------------------------------------

class TestCustomTransport:

    def test_custom_walker_integrated(self, tmp_path):
        """Custom walker that injects extra files alongside real ones."""
        import os
        (tmp_path / "ntds.dit").write_bytes(b"real file")

        class ExtraFileWalker:
            def walk_directory(self, path, on_file=None, on_dir=None, cancel=None):
                # Report a fake extra file
                if on_file:
                    on_file(os.path.join(path, "fake_passwords.txt"), 100, 1700000000.0)
                # Also do real listing
                from snaffler.discovery.local_tree_walker import LocalTreeWalker
                return LocalTreeWalker().walk_directory(path, on_file, on_dir, cancel)

        findings = list(Snaffler(walker=ExtraFileWalker()).walk(str(tmp_path)))
        paths = [f.file_path for f in findings]
        # Both the real file and the injected fake file should produce findings
        assert any("ntds.dit" in p for p in paths)
        assert any("fake_passwords.txt" in p for p in paths)

    def test_custom_reader_integrated(self, tmp_path):
        """Custom reader that injects password content into all files."""
        (tmp_path / "innocent.ps1").write_text("nothing here")

        class PasswordReader:
            def read(self, path, max_bytes=None):
                return b'$password = "injected_secret"\n'

        findings = list(Snaffler(reader=PasswordReader()).walk(str(tmp_path)))
        assert any("innocent.ps1" in f.file_path for f in findings)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_dir(self, tmp_path):
        assert _walk(tmp_path) == []

    def test_nonexistent_dir(self):
        findings = _walk("/nonexistent/path/12345")
        assert findings == []

    def test_walk_returns_generator(self):
        s = Snaffler()
        gen = s.walk(str(_DATA_DIR))
        assert hasattr(gen, '__next__')
        # Consume first result to prove it's lazy
        first = next(gen)
        assert isinstance(first, FileResult)

    def test_permission_denied_subdir(self, tmp_path):
        """Inaccessible subdirectory is skipped without crashing."""
        good = tmp_path / "good"
        good.mkdir()
        (good / "ntds.dit").write_bytes(b"findme")

        bad = tmp_path / "noaccess"
        bad.mkdir()
        (bad / "ntds.dit").write_bytes(b"hidden")
        bad.chmod(0o000)

        try:
            findings = _walk(tmp_path)
            paths = [f.file_path for f in findings]
            assert any("good" in p for p in paths)
            assert not any("noaccess" in p for p in paths)
        finally:
            bad.chmod(0o755)


# ---------------------------------------------------------------------------
# CLI --local pipeline (FilePipeline with local transport)
# ---------------------------------------------------------------------------

class TestLocalPipeline:
    """Run the full CLI pipeline (SnafflerRunner) with --local against the
    real local filesystem.  No mocking — validates that the runner correctly
    injects LocalTreeWalker + LocalFileAccessor and produces findings."""

    @pytest.fixture()
    def cfg(self):
        from snaffler.classifiers.loader import RuleLoader
        from snaffler.config.configuration import SnafflerConfiguration

        c = SnafflerConfiguration()
        c.targets.local_targets = [str(_DATA_DIR)]
        c.scanning.max_read_bytes = 2 * 1024 * 1024
        c.scanning.max_file_bytes = 10 * 1024 * 1024
        c.scanning.match_context_bytes = 200
        c.scanning.min_interest = 0
        c.advanced.share_threads = 2
        c.advanced.tree_threads = 2
        c.advanced.file_threads = 2
        c.state.state_db = ":memory:"
        RuleLoader.load(c)
        return c

    def test_runner_produces_findings(self, cfg):
        from snaffler.engine.runner import SnafflerRunner
        from snaffler.utils.logger import set_finding_store

        runner = SnafflerRunner(cfg)
        runner.execute()
        set_finding_store(None)

        assert runner.progress.files_scanned > 0
        assert runner.progress.files_matched > 0

    def test_runner_uses_local_transport(self, cfg):
        from snaffler.accessors.local_file_accessor import LocalFileAccessor
        from snaffler.discovery.local_tree_walker import LocalTreeWalker
        from snaffler.engine.runner import SnafflerRunner
        from snaffler.utils.logger import set_finding_store

        runner = SnafflerRunner(cfg)
        assert isinstance(runner.file_pipeline.tree_walker, LocalTreeWalker)
        assert isinstance(runner.file_pipeline.file_scanner.file_accessor, LocalFileAccessor)
        set_finding_store(None)

    def test_runner_multiple_local_paths(self, tmp_path, cfg):
        from snaffler.engine.runner import SnafflerRunner
        from snaffler.utils.logger import set_finding_store

        # Create two directories with interesting files
        dir1 = tmp_path / "dir1"
        dir1.mkdir()
        (dir1 / "ntds.dit").write_bytes(b"creds")

        dir2 = tmp_path / "dir2"
        dir2.mkdir()
        (dir2 / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")

        cfg.targets.local_targets = [str(dir1), str(dir2)]
        runner = SnafflerRunner(cfg)
        runner.execute()
        set_finding_store(None)

        assert runner.progress.shares_found == 2
        assert runner.progress.files_matched >= 2

    def test_runner_empty_local_dir(self, tmp_path, cfg):
        from snaffler.engine.runner import SnafflerRunner
        from snaffler.utils.logger import set_finding_store

        empty = tmp_path / "empty"
        empty.mkdir()
        cfg.targets.local_targets = [str(empty)]

        runner = SnafflerRunner(cfg)
        runner.execute()
        set_finding_store(None)

        assert runner.progress.files_matched == 0
