"""Tests for the public library API (Snaffler).

Uses real default rules — no mocking of the classification engine.
"""

import io
import os
import types
import zipfile

import pytest

from snaffler.api import Snaffler, SnafflerEngine
from snaffler.analysis.file_scanner import FileCheckResult, FileCheckStatus
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.rules import Triage

DATA_ROOT = os.path.join(os.path.dirname(__file__), os.pardir, "data")
TEST_ARCHIVE = os.path.join(DATA_ROOT, "test_archive.zip")
TEST_KEY_PEM = os.path.join(DATA_ROOT, "test_combined.pem")  # has private key
TEST_CERT_PEM = os.path.join(DATA_ROOT, "test_cert.pem")  # no private key


def _zip_bytes(*members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


# ------------------------------------------------------------------ constructor


class TestConstructor:

    def test_default_rules_load(self):
        s = Snaffler()
        assert s._scanner.rule_evaluator is not None

    def test_custom_rule_dir(self, tmp_path):
        rule_file = tmp_path / "custom.toml"
        rule_file.write_text("""
[[ClassifierRules]]
RuleName = "CustomTestRule"
EnumerationScope = "FileEnumeration"
MatchAction = "Snaffle"
MatchLocation = "FileName"
WordListType = "Exact"
WordList = ["custom_secret.txt"]
Triage = "Red"
""")
        s = Snaffler(rule_dir=str(tmp_path))
        check = s.check_file("custom_secret.txt", 100, 1700000000.0)
        assert check.status == FileCheckStatus.SNAFFLE

    def test_empty_rule_dir_raises(self, tmp_path):
        with pytest.raises(RuntimeError, match="No classification rules"):
            Snaffler(rule_dir=str(tmp_path))

    def test_backwards_compat_alias(self):
        assert SnafflerEngine is Snaffler

    def test_default_walker_and_reader(self):
        s = Snaffler()
        from snaffler.discovery.local_tree_walker import LocalTreeWalker
        from snaffler.discovery.tree import TreeWalker
        from snaffler.accessors.local_file_accessor import LocalFileAccessor
        from snaffler.accessors.file_accessor import FileAccessor
        assert isinstance(s._walker, LocalTreeWalker)
        assert isinstance(s._walker, TreeWalker)
        assert isinstance(s._reader, LocalFileAccessor)
        assert isinstance(s._reader, FileAccessor)

    def test_custom_walker_and_reader(self):
        walker = object()
        reader = object()
        s = Snaffler(walker=walker, reader=reader)
        assert s._walker is walker
        assert s._reader is reader

    def test_cert_passwords_default_matches_cli(self):
        """Library API uses the same default cert passwords as CLI."""
        from snaffler.config.configuration import DEFAULT_CERT_PASSWORDS, ScanningConfig
        s = Snaffler()
        # CertificateChecker merges its DEFAULT_PASSWORDS + custom_passwords
        # The CLI's cert_passwords (= DEFAULT_CERT_PASSWORDS) should all
        # appear in the checker's password list.
        checker_passwords = s._scanner.cert_checker.passwords
        cli_passwords = ScanningConfig().cert_passwords
        for pw in cli_passwords:
            assert pw in checker_passwords, f"CLI password {pw!r} missing from checker"
        for pw in DEFAULT_CERT_PASSWORDS:
            assert pw in checker_passwords, f"DEFAULT password {pw!r} missing from checker"

    def test_cert_passwords_custom(self):
        s = Snaffler(cert_passwords=["test123"])
        assert "test123" in s._scanner.cert_checker.passwords

    def test_max_depth_stored(self):
        s = Snaffler(max_depth=3)
        assert s._max_depth == 3

    def test_max_depth_default_none(self):
        s = Snaffler()
        assert s._max_depth is None


# ------------------------------------------------------------------ LocalFileAccessor


class TestLocalFileAccessor:

    def test_copy_to_local(self, tmp_path):
        """LocalFileAccessor.copy_to_local copies a file to dest_root."""
        from snaffler.accessors.local_file_accessor import LocalFileAccessor
        src = tmp_path / "source.txt"
        src.write_text("secret data")
        dest = tmp_path / "output"
        accessor = LocalFileAccessor()
        accessor.copy_to_local(str(src), str(dest))
        assert (dest / "source.txt").read_text() == "secret data"

    def test_copy_to_local_creates_dest_dir(self, tmp_path):
        """copy_to_local creates the destination directory if needed."""
        from snaffler.accessors.local_file_accessor import LocalFileAccessor
        src = tmp_path / "file.txt"
        src.write_text("data")
        dest = tmp_path / "new" / "nested" / "dir"
        accessor = LocalFileAccessor()
        accessor.copy_to_local(str(src), str(dest))
        assert (dest / "file.txt").read_text() == "data"


# ------------------------------------------------------------------ check_dir


class TestCheckDir:

    def test_normal_dir_passes(self):
        s = Snaffler()
        assert s.check_dir("//server/share/Projects") is True

    def test_exclude_glob_rejected(self):
        s = Snaffler(exclude_unc=["*/Windows/*"])
        assert s.check_dir("//server/share/Windows/System32") is False

    def test_discard_rule_rejects(self):
        s = Snaffler()
        # Default rules discard winsxs
        assert s.check_dir("//server/share/winsxs") is False

    def test_check_dir_delegates_to_walker(self):
        """check_dir() on a TreeWalker delegates to _should_scan_directory."""
        s = Snaffler(exclude_unc=["*/skipme*"])
        from snaffler.discovery.tree import TreeWalker
        assert isinstance(s._walker, TreeWalker)
        # The walker and check_dir should agree on the same paths
        assert s.check_dir("/some/skipme/dir") is False
        assert s._walker._should_scan_directory("/some/skipme/dir") is False
        assert s.check_dir("/some/okdir") is True
        assert s._walker._should_scan_directory("/some/okdir") is True

    def test_check_dir_duck_typed_walker(self):
        """check_dir() works with duck-typed walkers (not TreeWalker)."""
        class DuckWalker:
            def walk_directory(self, path, on_file=None, on_dir=None, cancel=None):
                return []

        s = Snaffler(walker=DuckWalker(), exclude_unc=["*/skipme*"])
        assert s.check_dir("/some/skipme/dir") is False
        assert s.check_dir("/some/okdir") is True


# ------------------------------------------------------------------ check_file


class TestCheckFile:

    def test_jpg_discarded(self):
        s = Snaffler()
        check = s.check_file("//srv/share/photo.jpg", 50000, 1700000000.0)
        assert check.status == FileCheckStatus.DISCARD

    def test_ntds_dit_snaffle_black(self):
        s = Snaffler()
        check = s.check_file("//srv/share/ntds.dit", 1000000, 1700000000.0)
        assert check.status == FileCheckStatus.SNAFFLE
        assert check.result is not None
        assert check.result.triage == Triage.BLACK

    def test_ps1_needs_content(self):
        s = Snaffler()
        check = s.check_file("//srv/share/deploy.ps1", 500, 1700000000.0)
        assert check.status == FileCheckStatus.NEEDS_CONTENT

    def test_pfx_check_keys(self):
        s = Snaffler()
        check = s.check_file("//srv/share/cert.pfx", 2000, 1700000000.0)
        assert check.status == FileCheckStatus.CHECK_KEYS

    def test_zip_peek_archive(self):
        s = Snaffler()
        check = s.check_file("//srv/share/backup.zip", 5000, 1700000000.0)
        assert check.status == FileCheckStatus.PEEK_ARCHIVE

    def test_returns_file_check_result(self):
        s = Snaffler()
        check = s.check_file("//srv/share/something.txt", 100, 1700000000.0)
        assert isinstance(check, FileCheckResult)


# ------------------------------------------------------------------ scan_content


class TestScanContent:

    def test_with_prior_password_match(self):
        s = Snaffler()
        prior = s.check_file("//srv/share/config.ps1", 500, 1700000000.0)
        assert prior.status == FileCheckStatus.NEEDS_CONTENT

        data = b'$password = "hunter2"\n'
        result = s.scan_content(data, prior=prior)
        assert isinstance(result, FileResult)
        assert result.triage.level >= 1

    def test_no_match_returns_none(self):
        s = Snaffler()
        prior = s.check_file("//srv/share/script.ps1", 100, 1700000000.0)
        data = b"Write-Host 'Hello World'\n"
        result = s.scan_content(data, prior=prior)
        assert result is None

    def test_standalone_mode(self):
        s = Snaffler()
        data = b'password = "secret123"\n'
        result = s.scan_content(
            data,
            file_path="//srv/share/app.config",
            size=100,
            mtime_epoch=1700000000.0,
        )
        assert isinstance(result, FileResult)

    def test_standalone_discarded_file(self):
        s = Snaffler()
        data = b"doesn't matter"
        result = s.scan_content(
            data,
            file_path="//srv/share/app.dll",
            size=100,
            mtime_epoch=1700000000.0,
        )
        assert result is None

    def test_standalone_missing_args_raises(self):
        s = Snaffler()
        with pytest.raises(ValueError, match="file_path.*required"):
            s.scan_content(b"data")

    def test_black_early_exit(self):
        s = Snaffler()
        check = s.check_file("//srv/share/ntds.dit", 1000000, 1700000000.0)
        assert check.status == FileCheckStatus.SNAFFLE
        assert check.result.triage == Triage.BLACK

    def test_match_filter_suppresses(self):
        s = Snaffler(match_filter="nomatch_xyz_pattern")
        prior = s.check_file("//srv/share/deploy.ps1", 500, 1700000000.0)
        data = b'$password = "hunter2"\n'
        result = s.scan_content(data, prior=prior)
        assert result is None

    def test_relay_targeted_rules(self):
        s = Snaffler()
        # .config files get RELAY'd to specific content rules
        prior = s.check_file("//srv/share/web.config", 500, 1700000000.0)
        assert prior.status == FileCheckStatus.NEEDS_CONTENT
        # Content rule names should be populated by RELAY
        assert len(prior.content_rule_names) > 0


# ------------------------------------------------------------------ check_certificate


class TestCheckCertificate:

    def test_private_key_found(self):
        s = Snaffler()
        with open(TEST_KEY_PEM, "rb") as f:
            data = f.read()
        result = s.check_certificate(
            "//srv/share/server.pem", len(data), 1700000000.0, data
        )
        assert isinstance(result, FileResult)
        assert result.triage == Triage.RED
        assert "HasPrivateKey" in result.context

    def test_no_private_key_returns_none(self):
        s = Snaffler()
        with open(TEST_CERT_PEM, "rb") as f:
            data = f.read()
        result = s.check_certificate(
            "//srv/share/cert.pem", len(data), 1700000000.0, data
        )
        assert result is None


# ------------------------------------------------------------------ peek_archive


class TestPeekArchive:

    def test_zip_with_sensitive_member(self):
        s = Snaffler()
        zip_data = _zip_bytes(
            ("passwords.txt", b"admin:hunter2"),
            ("readme.txt", b"nothing here"),
        )
        result = s.peek_archive(
            "//srv/share/backup.zip", len(zip_data), 1700000000.0, zip_data
        )
        assert isinstance(result, FileResult)
        assert result.triage.level >= Triage.RED.level
        assert "\u2192passwords.txt" in result.file_path

    def test_empty_archive_returns_none(self):
        s = Snaffler()
        zip_data = _zip_bytes(("readme.txt", b"nothing"))
        result = s.peek_archive(
            "//srv/share/stuff.zip", len(zip_data), 1700000000.0, zip_data
        )
        assert result is None

    def test_real_test_archive(self):
        s = Snaffler()
        with open(TEST_ARCHIVE, "rb") as f:
            zip_data = f.read()
        result = s.peek_archive(
            "//srv/share/test_archive.zip", len(zip_data), 1700000000.0, zip_data
        )
        assert isinstance(result, FileResult)
        assert result.triage == Triage.BLACK


# ------------------------------------------------------------------ output filters


class TestOutputFilters:

    def test_min_interest_filters(self):
        s = Snaffler(min_interest=3)  # BLACK only
        check = s.check_file("//srv/share/deploy.ps1", 500, 1700000000.0)
        data = b'$password = "hunter2"\n'
        result = s.scan_content(data, prior=check)
        # Password match is RED (2), not BLACK (3) — filtered out
        assert result is None

    def test_match_filter_passes(self):
        s = Snaffler(match_filter="password")
        prior = s.check_file("//srv/share/deploy.ps1", 500, 1700000000.0)
        data = b'$password = "hunter2"\n'
        result = s.scan_content(data, prior=prior)
        # Should pass because content matches "password"
        assert isinstance(result, FileResult)


# ------------------------------------------------------------------ full two-phase flow


class TestFullFlow:

    def test_check_then_scan(self):
        s = Snaffler()
        check = s.check_file("//srv/share/web.config", 200, 1700000000.0)

        if check.status == FileCheckStatus.NEEDS_CONTENT:
            data = b'<connectionStrings><add connectionString="Server=db;Password=secret"/></connectionStrings>'
            result = s.scan_content(data, prior=check)
            assert isinstance(result, FileResult)
        elif check.status == FileCheckStatus.SNAFFLE:
            assert check.result is not None

    def test_check_file_then_cert(self):
        s = Snaffler()
        check = s.check_file("//srv/share/server.pfx", 2000, 1700000000.0)
        assert check.status == FileCheckStatus.CHECK_KEYS

        with open(TEST_KEY_PEM, "rb") as f:
            data = f.read()
        result = s.check_certificate(
            "//srv/share/server.pfx", 2000, 1700000000.0, data
        )
        assert isinstance(result, FileResult)
        assert result.triage == Triage.RED

    def test_check_file_then_archive(self):
        s = Snaffler()
        check = s.check_file("//srv/share/backup.zip", 5000, 1700000000.0)
        assert check.status == FileCheckStatus.PEEK_ARCHIVE

        zip_data = _zip_bytes(("id_rsa", b"private key data"))
        result = s.peek_archive(
            "//srv/share/backup.zip", 5000, 1700000000.0, zip_data
        )
        assert isinstance(result, FileResult)
        assert result.triage.level >= Triage.RED.level


# ------------------------------------------------------------------ regression tests


class TestRegressions:

    def test_relay_plus_snaffle_still_scans_content(self):
        """RELAY + non-BLACK SNAFFLE must not skip content scan."""
        s = Snaffler()
        # .config files get RELAY'd; if a SNAFFLE also fires,
        # content scan must still run
        check = s.check_file("//srv/share/web.config", 200, 1700000000.0)
        assert check.status == FileCheckStatus.NEEDS_CONTENT
        assert check._can_scan_content is True

        data = b'<connectionStrings><add connectionString="Server=db;Password=secret"/></connectionStrings>'
        result = s.scan_content(data, prior=check)
        assert isinstance(result, FileResult)

    def test_scan_content_with_snaffle_prior(self):
        """scan_content with a SNAFFLE prior returns the finding unchanged."""
        s = Snaffler()
        check = s.check_file("//srv/share/ntds.dit", 1000000, 1700000000.0)
        assert check.status == FileCheckStatus.SNAFFLE

        result = s.scan_content(b"irrelevant", prior=check)
        assert isinstance(result, FileResult)
        assert result.triage == Triage.BLACK

    def test_standalone_scan_content_with_pfx(self):
        """Standalone scan_content on a .pfx delegates cert check via scan_with_data."""
        s = Snaffler()
        with open(TEST_KEY_PEM, "rb") as f:
            data = f.read()
        result = s.scan_content(
            data,
            file_path="//srv/share/cert.pfx",
            size=len(data),
            mtime_epoch=1700000000.0,
        )
        assert isinstance(result, FileResult)
        assert result.triage == Triage.RED

    def test_standalone_scan_content_with_zip(self):
        """Standalone scan_content on a .zip delegates archive peek via scan_with_data."""
        s = Snaffler()
        zip_data = _zip_bytes(("passwords.txt", b"admin:hunter2"))
        result = s.scan_content(
            zip_data,
            file_path="//srv/share/backup.zip",
            size=len(zip_data),
            mtime_epoch=1700000000.0,
        )
        assert isinstance(result, FileResult)
        assert result.triage.level >= Triage.RED.level


# ------------------------------------------------------------------ walk()


class TestWalk:

    def test_finds_sensitive_file(self, tmp_path):
        """walk() finds ntds.dit (BLACK snaffle) in a local directory."""
        (tmp_path / "ntds.dit").write_bytes(b"fake ntds data")
        s = Snaffler()
        findings = list(s.walk(str(tmp_path)))
        assert len(findings) >= 1
        assert any(f.triage == Triage.BLACK for f in findings)
        assert any("ntds.dit" in f.file_path for f in findings)

    def test_finds_passwords_txt(self, tmp_path):
        """walk() finds passwords.txt (RED/BLACK snaffle)."""
        (tmp_path / "passwords.txt").write_bytes(b"admin:hunter2")
        s = Snaffler()
        findings = list(s.walk(str(tmp_path)))
        assert len(findings) >= 1
        assert any("passwords.txt" in f.file_path for f in findings)

    def test_skips_discarded_extension(self, tmp_path):
        """walk() ignores .jpg files (discarded by default rules)."""
        (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0")
        s = Snaffler()
        findings = list(s.walk(str(tmp_path)))
        assert not any("photo.jpg" in f.file_path for f in findings)

    def test_recurses_into_subdirs(self, tmp_path):
        """walk() finds files in nested subdirectories."""
        sub = tmp_path / "level1" / "level2"
        sub.mkdir(parents=True)
        (sub / "ntds.dit").write_bytes(b"deep nested")
        s = Snaffler()
        findings = list(s.walk(str(tmp_path)))
        assert len(findings) >= 1
        assert any("ntds.dit" in f.file_path for f in findings)

    def test_exclude_unc_skips_dir(self, tmp_path):
        """walk() respects exclude_unc glob patterns on local paths."""
        skip = tmp_path / "node_modules"
        skip.mkdir()
        (skip / "ntds.dit").write_bytes(b"should be skipped")
        s = Snaffler(exclude_unc=["*/node_modules*"])
        findings = list(s.walk(str(tmp_path)))
        assert not any("node_modules" in f.file_path for f in findings)

    def test_permission_denied_dir(self, tmp_path):
        """walk() gracefully handles inaccessible directories."""
        bad = tmp_path / "noaccess"
        bad.mkdir()
        (bad / "ntds.dit").write_bytes(b"hidden")
        bad.chmod(0o000)
        try:
            s = Snaffler()
            # Should not raise — errors are swallowed
            findings = list(s.walk(str(tmp_path)))
            # ntds.dit inside noaccess should not be found
            assert not any("noaccess" in f.file_path for f in findings)
        finally:
            bad.chmod(0o755)

    def test_content_scan_works(self, tmp_path):
        """walk() does content scanning (e.g. .ps1 with password)."""
        (tmp_path / "deploy.ps1").write_text('$password = "hunter2"\n')
        s = Snaffler()
        findings = list(s.walk(str(tmp_path)))
        assert len(findings) >= 1
        assert any("deploy.ps1" in f.file_path for f in findings)

    def test_empty_dir_yields_nothing(self, tmp_path):
        """walk() on an empty directory yields no findings."""
        s = Snaffler()
        findings = list(s.walk(str(tmp_path)))
        assert findings == []

    def test_custom_walker_called(self, tmp_path):
        """walk() uses the injected walker."""
        calls = []

        class FakeWalker:
            def walk_directory(self, path, on_file=None, on_dir=None, cancel=None):
                calls.append(path)
                if on_file:
                    on_file(os.path.join(path, "ntds.dit"), 100, 1700000000.0)
                return []

        class FakeReader:
            def read(self, path, max_bytes=None):
                return None

        s = Snaffler(walker=FakeWalker(), reader=FakeReader())
        findings = list(s.walk("/fake/root"))
        assert calls == ["/fake/root"]
        assert any("ntds.dit" in f.file_path for f in findings)

    def test_custom_reader_called(self, tmp_path):
        """walk() uses the injected reader for content scans."""
        read_calls = []

        class FakeWalker:
            def walk_directory(self, path, on_file=None, on_dir=None, cancel=None):
                if on_file:
                    on_file(os.path.join(path, "deploy.ps1"), 100, 1700000000.0)
                return []

        class FakeReader:
            def read(self, path, max_bytes=None):
                read_calls.append(path)
                return b'$password = "hunter2"\n'

        s = Snaffler(walker=FakeWalker(), reader=FakeReader())
        findings = list(s.walk("/fake/root"))
        assert len(read_calls) >= 1
        assert any("deploy.ps1" in f.file_path for f in findings)

    def test_returns_generator(self):
        """walk() returns a generator (lazy evaluation)."""
        s = Snaffler()
        result = s.walk("/nonexistent/path")
        assert hasattr(result, '__next__')

    def test_walk_with_min_interest(self, tmp_path):
        """walk() respects min_interest filter."""
        (tmp_path / "ntds.dit").write_bytes(b"critical")
        (tmp_path / "deploy.ps1").write_text('$password = "hunter2"\n')
        s = Snaffler(min_interest=3)  # BLACK only
        findings = list(s.walk(str(tmp_path)))
        # ntds.dit is BLACK (3), should pass
        assert any("ntds.dit" in f.file_path for f in findings)
        # password match in .ps1 is RED (2), should be filtered
        assert not any("deploy.ps1" in f.file_path for f in findings)

    def test_max_depth_zero_no_recurse(self, tmp_path):
        """max_depth=0 walks root only, no subdirectories."""
        (tmp_path / "ntds.dit").write_bytes(b"root level")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "ntds.dit").write_bytes(b"nested")
        s = Snaffler(max_depth=0)
        findings = list(s.walk(str(tmp_path)))
        assert any("ntds.dit" in f.file_path for f in findings)
        assert not any("subdir" in f.file_path for f in findings)

    def test_max_depth_one_recurses_once(self, tmp_path):
        """max_depth=1 walks root + one level of subdirs."""
        (tmp_path / "ntds.dit").write_bytes(b"root")
        sub = tmp_path / "level1"
        sub.mkdir()
        (sub / "ntds.dit").write_bytes(b"level 1")
        deep = sub / "level2"
        deep.mkdir()
        (deep / "ntds.dit").write_bytes(b"level 2")
        s = Snaffler(max_depth=1)
        findings = list(s.walk(str(tmp_path)))
        paths = [f.file_path for f in findings]
        assert any("level1" in p and "level2" not in p for p in paths)
        assert not any("level2" in p for p in paths)

    def test_max_depth_none_unlimited(self, tmp_path):
        """max_depth=None (default) recurses into all subdirs."""
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "ntds.dit").write_bytes(b"deep")
        s = Snaffler()
        findings = list(s.walk(str(tmp_path)))
        assert any("ntds.dit" in f.file_path for f in findings)
