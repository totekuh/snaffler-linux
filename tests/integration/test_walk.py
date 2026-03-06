"""
Integration test: Snaffler.walk() against the real local filesystem.

No mocking — real rules, real local tree walker, real local file reader,
real test data directory.  Validates that the library API produces correct
findings when pointed at a local directory tree.

Each test class covers a specific flag/feature with both positive tests
(flag produces expected effect) and negative tests (flag does NOT produce
false effects).
"""

import os
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

class TestWalkBasic:
    """Walk the entire tests/data/ tree and verify aggregate findings."""

    # -- positive --

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
            base = f.file_path.split("\u2192")[0]
            assert not base.startswith("//"), f"UNC path in walk(): {f.file_path}"

    def test_finds_black_severity(self):
        findings = _walk(_DATA_DIR)
        black = [f for f in findings if f.triage == Triage.BLACK]
        assert len(black) > 0

    def test_finds_red_severity(self):
        findings = _walk(_DATA_DIR)
        red = [f for f in findings if f.triage == Triage.RED]
        assert len(red) > 0

    def test_finds_yellow_severity(self):
        findings = _walk(_DATA_DIR)
        yellow = [f for f in findings if f.triage == Triage.YELLOW]
        assert len(yellow) > 0

    def test_finds_green_severity(self):
        findings = _walk(_DATA_DIR)
        green = [f for f in findings if f.triage == Triage.GREEN]
        assert len(green) > 0

    def test_finds_content_matches(self):
        """Content scan produces findings with match text."""
        findings = _walk(_DATA_DIR)
        with_match = [f for f in findings if f.match]
        assert len(with_match) > 0

    def test_walk_returns_generator(self):
        s = Snaffler()
        gen = s.walk(str(_DATA_DIR))
        assert hasattr(gen, '__next__')
        first = next(gen)
        assert isinstance(first, FileResult)

    # -- negative --

    def test_scans_more_files_than_matches(self):
        """Not every file is a finding — data dir has benign files too."""
        findings = _walk(_DATA_DIR)
        total_files = sum(1 for _ in _DATA_DIR.rglob("*") if _.is_file())
        assert len(findings) < total_files

    def test_benign_file_not_flagged(self, tmp_path):
        """A plain text file with no secrets should produce no findings."""
        (tmp_path / "readme.txt").write_text("This is a benign readme file.\n")
        findings = _walk(tmp_path)
        assert len(findings) == 0

    def test_benign_python_file_not_flagged(self, tmp_path):
        """A .py file with no secrets should produce no findings."""
        (tmp_path / "app.py").write_text("print('hello world')\n")
        findings = _walk(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Recursion / depth
# ---------------------------------------------------------------------------

class TestRecursion:

    # -- positive --

    def test_finds_files_in_subdirs(self):
        findings = _walk(_DATA_DIR)
        nested = [
            f for f in findings
            if any(d in f.file_path for d in ["relay_", "password_files", "gpp"])
        ]
        assert len(nested) > 0

    def test_finds_deeply_nested_files(self):
        findings = _walk(_DATA_DIR)
        gpp = [f for f in findings if "gpp" in f.file_path.lower()]
        assert len(gpp) > 0


# ---------------------------------------------------------------------------
# max_depth
# ---------------------------------------------------------------------------

class TestMaxDepth:

    # -- positive --

    def test_depth_zero_scans_root_files(self, tmp_path):
        """Depth 0 scans files directly in the root."""
        (tmp_path / "ntds.dit").write_bytes(b"root level")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "SAM").write_bytes(b"nested")

        findings = _walk(tmp_path, max_depth=0)
        paths = [f.file_path for f in findings]
        assert any("ntds.dit" in p for p in paths)

    def test_depth_one_includes_first_subdirs(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"root")
        level1 = root / "level1"
        level1.mkdir()
        (level1 / "SAM").write_bytes(b"first level")

        findings = _walk(root, max_depth=1)
        paths = [f.file_path for f in findings]
        assert any("ntds.dit" in p for p in paths)
        assert any("SAM" in p for p in paths)

    def test_depth_zero_fewer_than_unlimited(self):
        full = _walk(_DATA_DIR)
        shallow = _walk(_DATA_DIR, max_depth=0)
        assert len(shallow) < len(full)

    # -- negative --

    def test_depth_zero_skips_subdirectories(self, tmp_path):
        """Depth 0 does NOT scan files in subdirectories."""
        (tmp_path / "benign.txt").write_text("nothing\n")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "ntds.dit").write_bytes(b"nested secret")

        findings = _walk(tmp_path, max_depth=0)
        paths = [f.file_path for f in findings]
        assert not any("ntds.dit" in p for p in paths)

    def test_depth_one_skips_second_level(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        level1 = root / "level1"
        level1.mkdir()
        level2 = level1 / "level2"
        level2.mkdir()
        (level2 / "ntds.dit").write_bytes(b"too deep")

        findings = _walk(root, max_depth=1)
        paths = [f.file_path for f in findings]
        assert not any("ntds.dit" in p for p in paths)

    def test_unlimited_depth_finds_everything(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        deep = root / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "ntds.dit").write_bytes(b"very deep")

        findings = _walk(root)  # max_depth=None = unlimited
        paths = [f.file_path for f in findings]
        assert any("ntds.dit" in p for p in paths)


# ---------------------------------------------------------------------------
# exclude_unc
# ---------------------------------------------------------------------------

class TestExcludeUNC:

    # -- positive --

    def test_exclude_reduces_findings(self):
        full = _walk(_DATA_DIR)
        excl = _walk(_DATA_DIR, exclude_unc=["*/relay_*"])
        assert len(excl) < len(full)

    def test_excluded_paths_absent(self):
        findings = _walk(_DATA_DIR, exclude_unc=["*/archives*"])
        for f in findings:
            assert "archives" not in f.file_path

    def test_multiple_exclusions_stack(self):
        one = _walk(_DATA_DIR, exclude_unc=["*/relay_*"])
        two = _walk(_DATA_DIR, exclude_unc=["*/relay_*", "*gpp*"])
        assert len(two) < len(one)

    def test_exclude_specific_subdir(self, tmp_path):
        """Exclude a specific subdirectory by name."""
        keep = tmp_path / "keep"
        keep.mkdir()
        (keep / "ntds.dit").write_bytes(b"keep me")
        skip = tmp_path / "skip"
        skip.mkdir()
        (skip / "SAM").write_bytes(b"skip me")

        findings = _walk(tmp_path, exclude_unc=["*/skip*"])
        paths = [f.file_path for f in findings]
        assert any("ntds.dit" in p for p in paths)
        assert not any("SAM" in p for p in paths)

    # -- negative --

    def test_exclude_nonmatching_pattern_no_effect(self):
        """An exclude pattern that matches nothing doesn't reduce findings."""
        full = _walk(_DATA_DIR)
        excl = _walk(_DATA_DIR, exclude_unc=["*/zzz_nonexistent_dir_zzz*"])
        assert len(excl) == len(full)

    def test_non_excluded_dirs_still_scanned(self):
        """Excluding one dir doesn't affect sibling directories."""
        findings = _walk(_DATA_DIR, exclude_unc=["*/archives*"])
        # relay_ dirs should still produce findings
        relay = [f for f in findings if "relay_" in f.file_path]
        assert len(relay) > 0


# ---------------------------------------------------------------------------
# min_interest
# ---------------------------------------------------------------------------

class TestMinInterest:

    # -- positive --

    def test_higher_min_interest_fewer_findings(self):
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

    # -- negative --

    def test_min_interest_zero_includes_green(self):
        findings = _walk(_DATA_DIR, min_interest=0)
        green = [f for f in findings if f.triage == Triage.GREEN]
        assert len(green) > 0

    def test_min_interest_high_excludes_green_yellow(self):
        findings = _walk(_DATA_DIR, min_interest=2)
        assert not any(f.triage == Triage.GREEN for f in findings)
        assert not any(f.triage == Triage.YELLOW for f in findings)

    def test_min_interest_black_excludes_red(self):
        findings = _walk(_DATA_DIR, min_interest=3)
        assert not any(f.triage == Triage.RED for f in findings)

    def test_min_interest_impossible_level_no_findings(self):
        """Interest level higher than any rule produces no findings."""
        findings = _walk(_DATA_DIR, min_interest=99)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# match_filter
# ---------------------------------------------------------------------------

class TestMatchFilter:

    # -- positive --

    def test_match_filter_reduces_findings(self):
        all_findings = _walk(_DATA_DIR)
        filtered = _walk(_DATA_DIR, match_filter="password")
        assert len(filtered) < len(all_findings)
        assert len(filtered) > 0

    def test_match_filter_case_insensitive(self):
        lower = _walk(_DATA_DIR, match_filter="password")
        upper = _walk(_DATA_DIR, match_filter="PASSWORD")
        assert len(lower) == len(upper)

    def test_match_filter_by_rule_name(self):
        """Filter by rule name (e.g. 'KeepSSH') to isolate specific rules."""
        findings = _walk(_DATA_DIR, match_filter="KeepSSH")
        assert len(findings) > 0
        # All findings should be from SSH-related rules
        for f in findings:
            assert "ssh" in f.rule_name.lower() or "SSH" in f.rule_name

    def test_match_filter_by_extension(self):
        """Filter by file extension."""
        findings = _walk(_DATA_DIR, match_filter=r"\.pem")
        assert len(findings) > 0
        for f in findings:
            assert ".pem" in f.file_path

    # -- negative --

    def test_match_filter_impossible_pattern(self):
        findings = _walk(_DATA_DIR, match_filter="zzz_impossible_pattern_zzz")
        assert len(findings) == 0

    def test_match_filter_does_not_prevent_scanning(self, tmp_path):
        """Filter suppresses output, but scanning still happens."""
        (tmp_path / "ntds.dit").write_bytes(b"data")
        (tmp_path / "SAM").write_bytes(b"data")

        # Match only ntds — SAM should not appear
        findings = _walk(tmp_path, match_filter="ntds")
        paths = [f.file_path for f in findings]
        assert any("ntds.dit" in p for p in paths)
        assert not any("SAM" in p for p in paths)


# ---------------------------------------------------------------------------
# max_read_bytes
# ---------------------------------------------------------------------------

class TestMaxReadBytes:

    # -- positive --

    def test_default_produces_content_matches(self):
        """Default max_read_bytes reads enough to trigger content rules."""
        s = Snaffler()
        findings = list(s.walk(str(_DATA_DIR)))
        with_match = [f for f in findings if f.match]
        assert len(with_match) > 0

    def test_explicit_max_read_bytes_works(self, tmp_path):
        (tmp_path / "deploy.ps1").write_text('$password = "hunter2"\n')
        findings = _walk(tmp_path, max_read_bytes=4 * 1024 * 1024)
        assert any("deploy.ps1" in f.file_path for f in findings)

    # -- negative --

    def test_tiny_max_read_bytes_blocks_content_scanning(self, tmp_path):
        """max_read_bytes=1 effectively prevents meaningful content scanning."""
        (tmp_path / "deploy.ps1").write_text('$password = "hunter2"\n')
        findings = _walk(tmp_path, max_read_bytes=1)
        ps1 = [f for f in findings if "deploy.ps1" in f.file_path]
        # May still match by filename rule, but content match should be empty
        content_matches = [f for f in ps1 if f.match and "password" in str(f.match).lower()]
        assert len(content_matches) == 0

    def test_zero_max_read_bytes_no_content_matches(self, tmp_path):
        """max_read_bytes=0 should not crash and produces no content matches."""
        (tmp_path / "deploy.ps1").write_text('$password = "hunter2"\n')
        # Should not crash
        findings = _walk(tmp_path, max_read_bytes=0)
        # No content-based matches possible
        content_matches = [f for f in findings if f.match and "password" in str(f.match).lower()]
        assert len(content_matches) == 0


# ---------------------------------------------------------------------------
# Content scanning specifics
# ---------------------------------------------------------------------------

class TestContentScanning:

    # -- positive --

    def test_ps1_password_detected(self, tmp_path):
        (tmp_path / "deploy.ps1").write_text('$password = "hunter2"\n')
        findings = _walk(tmp_path)
        assert any("deploy.ps1" in f.file_path for f in findings)
        ps1 = [f for f in findings if "deploy.ps1" in f.file_path]
        assert any(f.match for f in ps1)

    def test_config_connection_string_detected(self, tmp_path):
        (tmp_path / "web.config").write_text(
            '<connectionStrings>'
            '<add connectionString="Server=db;Password=secret"/>'
            '</connectionStrings>'
        )
        findings = _walk(tmp_path)
        assert any("web.config" in f.file_path for f in findings)

    def test_aws_keys_detected(self, tmp_path):
        (tmp_path / "creds.ps1").write_text(
            '$key = "AKIAIOSFODNN7EXAMPLE"\n'
            '$secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        )
        findings = _walk(tmp_path)
        assert any(f.match and "AKIA" in str(f.match) for f in findings)

    def test_inline_private_key_detected(self, tmp_path):
        (tmp_path / "script.sh").write_text(
            '#!/bin/bash\n'
            'KEY="-----BEGIN RSA PRIVATE KEY-----\n'
            'MIIBOgIBAAJBALfakekeymaterial\n'
            '-----END RSA PRIVATE KEY-----"\n'
        )
        findings = _walk(tmp_path)
        assert any("script.sh" in f.file_path for f in findings)

    # -- negative --

    def test_clean_ps1_no_findings(self, tmp_path):
        (tmp_path / "clean.ps1").write_text(
            'Write-Host "Hello World"\n'
            '$count = 42\n'
        )
        findings = _walk(tmp_path)
        ps1 = [f for f in findings if "clean.ps1" in f.file_path]
        content_matches = [f for f in ps1 if f.match]
        assert len(content_matches) == 0

    def test_clean_config_no_findings(self, tmp_path):
        (tmp_path / "app.config").write_text(
            '<configuration><appSettings>'
            '<add key="Theme" value="Dark"/>'
            '</appSettings></configuration>'
        )
        findings = _walk(tmp_path)
        config = [f for f in findings if "app.config" in f.file_path and f.match]
        assert len(config) == 0


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

class TestCertificates:

    # -- positive --

    def test_certificate_with_private_key(self, tmp_path):
        shutil.copy(_DATA_DIR / "test_combined.pem", tmp_path / "server.pem")
        findings = _walk(tmp_path)
        pem = [f for f in findings if "server.pem" in f.file_path]
        assert len(pem) >= 1
        assert any(f.triage == Triage.RED for f in pem)

    def test_standalone_private_key_detected(self, tmp_path):
        shutil.copy(_DATA_DIR / "test_key.pem", tmp_path / "private.pem")
        findings = _walk(tmp_path)
        key = [f for f in findings if "private.pem" in f.file_path]
        assert len(key) >= 1

    # -- negative --

    def test_certificate_without_private_key(self, tmp_path):
        shutil.copy(_DATA_DIR / "test_cert.pem", tmp_path / "cert.pem")
        findings = _walk(tmp_path)
        cert = [f for f in findings if "cert.pem" in f.file_path]
        assert not any(f.triage == Triage.RED for f in cert)


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------

class TestArchives:

    # -- positive --

    def test_sensitive_archive_members_found(self):
        findings = _walk(_ARCHIVE_DIR)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) > 0

    def test_archive_member_path_format(self):
        findings = _walk(_ARCHIVE_DIR)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        for f in archive_findings:
            archive_part, member_part = f.file_path.split("\u2192", 1)
            assert archive_part.endswith((".zip", ".rar", ".7z"))
            assert len(member_part) > 0

    def test_zip_finds_ssh_key(self):
        findings = _walk(_ARCHIVE_DIR)
        ssh = [f for f in findings if "\u2192" in f.file_path and "id_rsa" in f.file_path]
        assert len(ssh) >= 1

    def test_rar_finds_ssh_key(self, tmp_path):
        shutil.copy(_ARCHIVE_DIR / "sensitive_archive.rar", tmp_path)
        findings = _walk(tmp_path)
        ssh = [f for f in findings if "\u2192" in f.file_path and "id_rsa" in f.file_path]
        assert len(ssh) >= 1

    def test_raised_max_read_bytes_peeks_oversized(self, tmp_path):
        shutil.copy(_ARCHIVE_DIR / "oversized_archive.zip", tmp_path)
        findings = _walk(tmp_path, max_read_bytes=20 * 1024 * 1024)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) > 0

    # -- negative --

    def test_boring_archive_no_member_findings(self, tmp_path):
        shutil.copy(_ARCHIVE_DIR / "boring_archive.zip", tmp_path)
        findings = _walk(tmp_path)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) == 0

    def test_boring_rar_no_member_findings(self, tmp_path):
        shutil.copy(_ARCHIVE_DIR / "boring_archive.rar", tmp_path)
        findings = _walk(tmp_path)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) == 0

    def test_oversized_archive_not_peeked(self):
        findings = _walk(_ARCHIVE_DIR)
        oversized = [f for f in findings if "oversized_archive" in f.file_path and "\u2192" in f.file_path]
        assert len(oversized) == 0

    def test_lowering_max_read_bytes_blocks_all_peeking(self):
        findings = _walk(_ARCHIVE_DIR, max_read_bytes=1)
        archive_findings = [f for f in findings if "\u2192" in f.file_path]
        assert len(archive_findings) == 0


# ---------------------------------------------------------------------------
# Filename / extension / path matching
# ---------------------------------------------------------------------------

class TestFileMatching:

    # -- positive --

    def test_ntds_dit_detected(self, tmp_path):
        (tmp_path / "ntds.dit").write_bytes(b"data")
        findings = _walk(tmp_path)
        assert any("ntds.dit" in f.file_path for f in findings)
        ntds = [f for f in findings if "ntds.dit" in f.file_path]
        assert ntds[0].triage == Triage.BLACK

    def test_sam_file_detected(self, tmp_path):
        (tmp_path / "SAM").write_bytes(b"data")
        findings = _walk(tmp_path)
        assert any("SAM" in f.file_path for f in findings)

    def test_ssh_private_key_by_name(self, tmp_path):
        (tmp_path / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")
        findings = _walk(tmp_path)
        assert any("id_rsa" in f.file_path for f in findings)

    def test_ppk_extension_detected(self, tmp_path):
        (tmp_path / "key.ppk").write_text("PuTTY-User-Key-File-2: ssh-rsa\n")
        findings = _walk(tmp_path)
        assert any("key.ppk" in f.file_path for f in findings)

    # -- negative --

    def test_innocent_txt_not_flagged(self, tmp_path):
        (tmp_path / "notes.txt").write_text("meeting notes from tuesday\n")
        findings = _walk(tmp_path)
        assert len(findings) == 0

    def test_innocent_json_not_flagged(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "myapp", "version": "1.0.0"}\n')
        findings = _walk(tmp_path)
        json_findings = [f for f in findings if "package.json" in f.file_path]
        assert len(json_findings) == 0


# ---------------------------------------------------------------------------
# check_dir (library API)
# ---------------------------------------------------------------------------

class TestCheckDir:

    # -- positive --

    def test_normal_dir_allowed(self):
        s = Snaffler()
        assert s.check_dir("/some/project/src") is True

    def test_excluded_dir_rejected(self):
        s = Snaffler(exclude_unc=["*/node_modules*"])
        assert s.check_dir("/project/node_modules/lodash") is False

    # -- negative --

    def test_excluded_pattern_does_not_block_siblings(self):
        s = Snaffler(exclude_unc=["*/node_modules*"])
        assert s.check_dir("/project/src") is True
        assert s.check_dir("/project/lib") is True


# ---------------------------------------------------------------------------
# check_file + scan_content (two-phase API)
# ---------------------------------------------------------------------------

class TestTwoPhaseAPI:

    # -- positive --

    def test_check_file_needs_content(self):
        """A .ps1 file should return NEEDS_CONTENT for content scanning."""
        from snaffler.analysis.file_scanner import FileCheckStatus
        s = Snaffler()
        result = s.check_file("/fake/deploy.ps1", 100, 1700000000.0)
        assert result.status == FileCheckStatus.NEEDS_CONTENT

    def test_scan_content_finds_password(self):
        s = Snaffler()
        result = s.scan_content(
            b'$password = "hunter2"\n',
            file_path="/fake/deploy.ps1",
            size=30,
            mtime_epoch=1700000000.0,
        )
        assert result is not None
        assert result.match is not None

    def test_check_file_snaffle_for_black_file(self):
        """ntds.dit should be immediately snaffled (no content scan needed)."""
        from snaffler.analysis.file_scanner import FileCheckStatus
        s = Snaffler()
        result = s.check_file("/fake/ntds.dit", 1000, 1700000000.0)
        assert result.status == FileCheckStatus.SNAFFLE
        assert result.result.triage == Triage.BLACK

    # -- negative --

    def test_check_file_discards_uninteresting(self):
        """An image file should be discarded (no matching rule)."""
        from snaffler.analysis.file_scanner import FileCheckStatus
        s = Snaffler()
        result = s.check_file("/fake/photo.png", 100, 1700000000.0)
        assert result.status == FileCheckStatus.DISCARD

    def test_scan_content_clean_data(self):
        """Clean data produces no finding."""
        s = Snaffler()
        result = s.scan_content(
            b"nothing interesting here\n",
            file_path="/fake/app.ps1",
            size=30,
            mtime_epoch=1700000000.0,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Custom walker/reader (duck typing)
# ---------------------------------------------------------------------------

class TestCustomTransport:

    # -- positive --

    def test_custom_walker_injects_files(self, tmp_path):
        (tmp_path / "ntds.dit").write_bytes(b"real file")

        class ExtraFileWalker:
            def walk_directory(self, path, on_file=None, on_dir=None, cancel=None):
                if on_file:
                    on_file(os.path.join(path, "fake_passwords.txt"), 100, 1700000000.0)
                from snaffler.discovery.local_tree_walker import LocalTreeWalker
                return LocalTreeWalker().walk_directory(path, on_file, on_dir, cancel)

        findings = list(Snaffler(walker=ExtraFileWalker()).walk(str(tmp_path)))
        paths = [f.file_path for f in findings]
        assert any("ntds.dit" in p for p in paths)
        assert any("fake_passwords.txt" in p for p in paths)

    def test_custom_reader_overrides_content(self, tmp_path):
        (tmp_path / "innocent.ps1").write_text("nothing here")

        class PasswordReader:
            def read(self, path, max_bytes=None):
                return b'$password = "injected_secret"\n'

        findings = list(Snaffler(reader=PasswordReader()).walk(str(tmp_path)))
        assert any("innocent.ps1" in f.file_path for f in findings)

    # -- negative --

    def test_custom_reader_returning_none(self, tmp_path):
        """Reader returning None should not crash — file is silently skipped."""
        (tmp_path / "deploy.ps1").write_text("content")

        class NullReader:
            def read(self, path, max_bytes=None):
                return None

        findings = list(Snaffler(reader=NullReader()).walk(str(tmp_path)))
        # No content-based matches since reader returns None
        content_matches = [f for f in findings if f.match and "password" in str(f.match).lower()]
        assert len(content_matches) == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_dir(self, tmp_path):
        assert _walk(tmp_path) == []

    def test_nonexistent_dir(self):
        assert _walk("/nonexistent/path/12345") == []

    def test_permission_denied_subdir(self, tmp_path):
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

    def test_symlink_to_file(self, tmp_path):
        """Symlinked files are scanned normally."""
        real = tmp_path / "real"
        real.mkdir()
        (real / "ntds.dit").write_bytes(b"data")
        link = tmp_path / "link"
        link.mkdir()
        (link / "ntds.dit").symlink_to(real / "ntds.dit")

        findings = _walk(link)
        assert any("ntds.dit" in f.file_path for f in findings)

    def test_empty_file(self, tmp_path):
        """A 0-byte sensitive file is still flagged by name."""
        (tmp_path / "ntds.dit").write_bytes(b"")
        findings = _walk(tmp_path)
        assert any("ntds.dit" in f.file_path for f in findings)

    def test_large_number_of_files(self, tmp_path):
        """Walk handles a directory with many files."""
        for i in range(50):
            (tmp_path / f"file_{i}.txt").write_text(f"content {i}\n")
        (tmp_path / "ntds.dit").write_bytes(b"secret")
        findings = _walk(tmp_path)
        # Should find ntds.dit among the noise
        assert any("ntds.dit" in f.file_path for f in findings)


# ---------------------------------------------------------------------------
# Combined flags
# ---------------------------------------------------------------------------

class TestCombinedFlags:

    def test_exclude_plus_min_interest(self):
        full = _walk(_DATA_DIR)
        filtered = _walk(_DATA_DIR, exclude_unc=["*/relay_*"], min_interest=2)
        assert 0 < len(filtered) < len(full)

    def test_exclude_plus_match_filter(self):
        findings = _walk(_DATA_DIR, exclude_unc=["*/archives*"], match_filter="password")
        assert len(findings) > 0
        for f in findings:
            assert "archives" not in f.file_path

    def test_depth_plus_exclude(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"root")

        skip = root / "skipme"
        skip.mkdir()
        (skip / "SAM").write_bytes(b"skip")

        keep = root / "keep"
        keep.mkdir()
        (keep / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")

        deep = keep / "deep"
        deep.mkdir()
        (deep / "SYSTEM").write_bytes(b"too deep")

        findings = _walk(root, max_depth=1, exclude_unc=["*/skipme*"])
        paths = [f.file_path for f in findings]
        assert any("ntds.dit" in p for p in paths)
        assert any("id_rsa" in p for p in paths)
        assert not any("SAM" in p for p in paths)
        assert not any("SYSTEM" in p for p in paths)

    def test_match_filter_plus_min_interest(self):
        findings = _walk(_DATA_DIR, match_filter="password", min_interest=2)
        # Very restrictive — should still find something
        all_findings = _walk(_DATA_DIR)
        assert len(findings) < len(all_findings)

    def test_match_filter_plus_exclude_plus_depth(self, tmp_path):
        """All three filters combined."""
        root = tmp_path / "root"
        root.mkdir()
        (root / "deploy.ps1").write_text('$password = "hunter2"\n')

        skip = root / "skipme"
        skip.mkdir()
        (skip / "creds.ps1").write_text('$password = "skipped"\n')

        keep = root / "keep"
        keep.mkdir()
        (keep / "app.ps1").write_text('$password = "kept"\n')

        deep = keep / "deep"
        deep.mkdir()
        (deep / "hidden.ps1").write_text('$password = "hidden"\n')

        findings = _walk(root, max_depth=1, exclude_unc=["*/skipme*"], match_filter="password")
        paths = [f.file_path for f in findings]
        assert any("deploy.ps1" in p for p in paths)
        assert any("app.ps1" in p for p in paths)
        assert not any("creds.ps1" in p for p in paths)  # excluded dir
        assert not any("hidden.ps1" in p for p in paths)  # too deep
