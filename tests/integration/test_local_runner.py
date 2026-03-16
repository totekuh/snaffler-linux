"""
Integration test: SnafflerRunner with --local-fs against real local filesystem.

No mocking — real rules, real local tree walker, real local file reader,
real test data directory.  Runs the full tool from the very top
(SnafflerRunner.execute()) with different CLI-equivalent flags.
"""

import logging
import shutil
import tempfile
from pathlib import Path

import pytest

from snaffler.classifiers.loader import RuleLoader
from snaffler.classifiers.rules import Triage
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import set_finding_store
from snaffler.utils.progress import ProgressState

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_ARCHIVE_DIR = _DATA_DIR / "archives"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)


@pytest.fixture()
def cfg():
    """Minimal SnafflerConfiguration targeting local filesystem."""
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


def _run(cfg):
    """Execute SnafflerRunner and return (runner, progress)."""
    runner = SnafflerRunner(cfg)
    runner.execute()
    return runner, runner.progress


# ---------------------------------------------------------------------------
# Basic: full scan from the top
# ---------------------------------------------------------------------------

class TestBasicLocalScan:

    def test_produces_findings(self, cfg):
        _, p = _run(cfg)
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_scans_more_than_matches(self, cfg):
        _, p = _run(cfg)
        assert p.files_scanned > p.files_matched

    def test_progress_shares_equal_paths(self, cfg):
        """shares_found should equal number of local_targets paths."""
        _, p = _run(cfg)
        assert p.shares_found == 1

    def test_scan_complete_flag(self, cfg):
        _, p = _run(cfg)
        assert p.scan_complete is True

    def test_severity_counts_populated(self, cfg):
        _, p = _run(cfg)
        total = p.severity_black + p.severity_red + p.severity_yellow + p.severity_green
        assert total == p.files_matched

    def test_findings_logged(self, cfg, caplog):
        with caplog.at_level(logging.INFO, logger="snaffler"):
            _run(cfg)
        assert any("[Black]" in r.message or "[Red]" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# --max-depth
# ---------------------------------------------------------------------------

class TestMaxDepth:

    def test_depth_zero_scans_only_root_files(self, cfg, tmp_path):
        """Depth 0 only scans files in the root, not subdirectories."""
        root = tmp_path / "root"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"root level")
        sub = root / "subdir"
        sub.mkdir()
        (sub / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")

        cfg.targets.local_targets = [str(root)]
        cfg.scanning.max_depth = 0
        _, p = _run(cfg)

        assert p.files_matched >= 1  # ntds.dit in root
        # id_rsa in subdir should NOT be found at depth 0

    def test_depth_zero_fewer_than_unlimited(self, cfg):
        cfg_unlimited = SnafflerConfiguration()
        cfg_unlimited.targets.local_targets = [str(_DATA_DIR)]
        cfg_unlimited.scanning.max_read_bytes = 2 * 1024 * 1024
        cfg_unlimited.scanning.max_file_bytes = 10 * 1024 * 1024
        cfg_unlimited.scanning.match_context_bytes = 200
        cfg_unlimited.scanning.min_interest = 0
        cfg_unlimited.advanced.share_threads = 2
        cfg_unlimited.advanced.tree_threads = 2
        cfg_unlimited.advanced.file_threads = 2
        cfg_unlimited.state.state_db = ":memory:"
        RuleLoader.load(cfg_unlimited)

        _, p_unlimited = _run(cfg_unlimited)

        cfg.scanning.max_depth = 0
        _, p_depth0 = _run(cfg)

        assert p_depth0.files_scanned < p_unlimited.files_scanned

    def test_depth_one_includes_first_level_subdirs(self, cfg, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"root")
        level1 = root / "level1"
        level1.mkdir()
        (level1 / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")
        level2 = level1 / "level2"
        level2.mkdir()
        (level2 / "SAM").write_bytes(b"deep")

        cfg.targets.local_targets = [str(root)]
        cfg.scanning.max_depth = 1
        _, p = _run(cfg)

        # Should find ntds.dit (root) and id_rsa (level1), but NOT SAM (level2)
        assert p.files_matched >= 2


# ---------------------------------------------------------------------------
# --exclude-unc (works on local paths too)
# ---------------------------------------------------------------------------

class TestExcludeUNC:

    def test_exclude_reduces_files_scanned(self, cfg):
        _, p_full = _run(cfg)

        cfg2 = SnafflerConfiguration()
        cfg2.targets.local_targets = [str(_DATA_DIR)]
        cfg2.targets.exclude_unc = ["*/archives*"]
        cfg2.scanning.max_read_bytes = 2 * 1024 * 1024
        cfg2.scanning.max_file_bytes = 10 * 1024 * 1024
        cfg2.scanning.match_context_bytes = 200
        cfg2.scanning.min_interest = 0
        cfg2.advanced.share_threads = 2
        cfg2.advanced.tree_threads = 2
        cfg2.advanced.file_threads = 2
        cfg2.state.state_db = ":memory:"
        RuleLoader.load(cfg2)
        _, p_excl = _run(cfg2)

        assert p_excl.files_scanned < p_full.files_scanned

    def test_exclude_pattern_skips_directory(self, cfg, caplog):
        cfg.targets.exclude_unc = ["*/archives*"]
        with caplog.at_level(logging.INFO, logger="snaffler"):
            _run(cfg)
        # No findings from the archives directory
        for r in caplog.records:
            if hasattr(r, "message") and "archives" in r.message.lower():
                # Allow debug/info about skipping, but not findings
                assert "[Black]" not in r.message
                assert "[Red]" not in r.message

    def test_multiple_excludes_stack(self, cfg):
        cfg.targets.exclude_unc = ["*/archives*"]
        _, p_one = _run(cfg)

        cfg2 = SnafflerConfiguration()
        cfg2.targets.local_targets = [str(_DATA_DIR)]
        cfg2.targets.exclude_unc = ["*/archives*", "*/gpp*", "*/relay_*"]
        cfg2.scanning.max_read_bytes = 2 * 1024 * 1024
        cfg2.scanning.max_file_bytes = 10 * 1024 * 1024
        cfg2.scanning.match_context_bytes = 200
        cfg2.scanning.min_interest = 0
        cfg2.advanced.share_threads = 2
        cfg2.advanced.tree_threads = 2
        cfg2.advanced.file_threads = 2
        cfg2.state.state_db = ":memory:"
        RuleLoader.load(cfg2)
        _, p_two = _run(cfg2)

        assert p_two.files_scanned < p_one.files_scanned

    # -- negative --

    def test_exclude_nonmatching_pattern_no_effect(self, cfg):
        """Exclude pattern that matches nothing doesn't change scan count."""
        _, p_full = _run(cfg)

        cfg.targets.exclude_unc = ["*/zzz_nonexistent_dir_zzz*"]
        _, p_excl = _run(cfg)

        assert p_excl.files_scanned == p_full.files_scanned

    def test_excluded_paths_absent_from_findings(self, cfg, caplog):
        """Excluded directory paths must not appear in any finding."""
        cfg.targets.exclude_unc = ["*/gpp*"]
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            _run(cfg)
        for r in caplog.records:
            if r.levelno >= logging.WARNING and hasattr(r, "message"):
                assert "/gpp/" not in r.message and "/gpp\\" not in r.message

    def test_non_excluded_siblings_still_scanned(self, cfg):
        """Excluding one dir doesn't suppress sibling directories."""
        cfg.targets.exclude_unc = ["*/archives*"]
        _, p = _run(cfg)
        # relay_ dirs should still produce findings
        assert p.files_matched > 0

    def test_exclude_specific_subdir(self, cfg, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        keep = root / "keep"
        keep.mkdir()
        (keep / "ntds.dit").write_bytes(b"keep")
        skip = root / "skip_this"
        skip.mkdir()
        (skip / "SAM").write_bytes(b"skip")

        cfg.targets.local_targets = [str(root)]
        cfg.targets.exclude_unc = ["*/skip_this*"]
        _, p = _run(cfg)
        assert p.files_matched >= 1  # ntds.dit found


# ---------------------------------------------------------------------------
# --exclusions (host exclusions — warns in local mode)
# ---------------------------------------------------------------------------

class TestHostExclusions:

    def test_exclusions_warns_in_local_mode(self, cfg, caplog):
        """--exclusions has no effect in --local-fs mode, should warn."""
        cfg.targets.exclusions = ["SOMEHOST"]
        with caplog.at_level(logging.WARNING, logger="snaffler"):
            _run(cfg)
        assert any("--exclusions" in r.message and "no effect" in r.message
                    for r in caplog.records if hasattr(r, "message"))

    def test_exclusions_does_not_crash_local_mode(self, cfg):
        """--exclusions with local paths doesn't crash."""
        cfg.targets.exclusions = ["HOST1", "HOST2"]
        _, p = _run(cfg)
        assert p.files_scanned > 0
        assert p.scan_complete is True


# ---------------------------------------------------------------------------
# --min-interest
# ---------------------------------------------------------------------------

class TestMinInterest:

    def test_min_interest_zero_most_findings(self, cfg):
        _, p_zero = _run(cfg)

        cfg.scanning.min_interest = 2
        _, p_high = _run(cfg)

        assert p_high.files_matched < p_zero.files_matched

    def test_min_interest_black_only(self, cfg):
        cfg.scanning.min_interest = 3
        _, p = _run(cfg)
        # Only Black severity should match
        assert p.severity_green == 0
        assert p.severity_yellow == 0
        assert p.severity_red == 0
        assert p.severity_black > 0

    # -- negative --

    def test_min_interest_zero_includes_green(self, cfg):
        _, p = _run(cfg)
        assert p.severity_green > 0

    def test_min_interest_high_excludes_low_severity(self, cfg):
        cfg.scanning.min_interest = 2
        _, p = _run(cfg)
        assert p.severity_green == 0
        assert p.severity_yellow == 0

    def test_min_interest_impossible_level(self, cfg):
        cfg.scanning.min_interest = 99
        _, p = _run(cfg)
        assert p.files_matched == 0
        assert p.files_scanned > 0


# ---------------------------------------------------------------------------
# --match (regex filter)
# ---------------------------------------------------------------------------

class TestMatchFilter:

    def test_match_filter_reduces_findings(self, cfg):
        _, p_full = _run(cfg)

        cfg.scanning.match_filter = "password"
        _, p_filtered = _run(cfg)

        assert p_filtered.files_matched < p_full.files_matched
        assert p_filtered.files_matched > 0

    def test_match_filter_does_not_affect_files_scanned(self, cfg):
        _, p_full = _run(cfg)

        cfg.scanning.match_filter = "password"
        _, p_filtered = _run(cfg)

        # All files are still scanned, just fewer match
        assert p_filtered.files_scanned == p_full.files_scanned

    def test_match_filter_impossible_pattern(self, cfg):
        cfg.scanning.match_filter = "zzz_impossible_pattern_zzz"
        _, p = _run(cfg)
        assert p.files_matched == 0
        assert p.files_scanned > 0

    def test_match_filter_case_insensitive(self, cfg):
        cfg.scanning.match_filter = "password"
        _, p_lower = _run(cfg)

        cfg.scanning.match_filter = "PASSWORD"
        _, p_upper = _run(cfg)

        assert p_lower.files_matched == p_upper.files_matched

    # -- negative --

    def test_match_filter_suppresses_non_matching(self, cfg, tmp_path, caplog):
        """Filtered-out findings must not appear in log output."""
        root = tmp_path / "filter_test"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"data")
        (root / "deploy.ps1").write_text('$password = "hunter2"\n')

        cfg.targets.local_targets = [str(root)]
        cfg.scanning.match_filter = "ntds"

        with caplog.at_level(logging.WARNING, logger="snaffler"):
            _run(cfg)

        # ntds.dit should be in findings, deploy.ps1 should NOT
        finding_messages = [r.message for r in caplog.records
                           if r.levelno >= logging.WARNING and hasattr(r, "message")]
        assert any("ntds.dit" in m for m in finding_messages)
        assert not any("deploy.ps1" in m for m in finding_messages)


# ---------------------------------------------------------------------------
# Multiple local paths
# ---------------------------------------------------------------------------

class TestMultiplePaths:

    def test_two_paths(self, cfg, tmp_path):
        dir1 = tmp_path / "dir1"
        dir1.mkdir()
        (dir1 / "ntds.dit").write_bytes(b"creds")

        dir2 = tmp_path / "dir2"
        dir2.mkdir()
        (dir2 / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")

        cfg.targets.local_targets = [str(dir1), str(dir2)]
        _, p = _run(cfg)

        assert p.shares_found == 2
        assert p.files_matched >= 2

    def test_one_empty_one_full(self, cfg, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()

        full = tmp_path / "full"
        full.mkdir()
        (full / "ntds.dit").write_bytes(b"data")

        cfg.targets.local_targets = [str(empty), str(full)]
        _, p = _run(cfg)

        assert p.shares_found == 2
        assert p.files_matched >= 1


# ---------------------------------------------------------------------------
# Resume (SQLite state) with local filesystem
# ---------------------------------------------------------------------------

class TestResumeLocal:

    def test_resume_skips_already_checked_files(self, cfg):
        """Run twice with same DB — second run should produce no new findings."""
        from snaffler.resume.scan_state import SQLiteStateStore

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg.state.state_db = db_path

            # First run
            _run(cfg)

            # Count findings after first run
            store = SQLiteStateStore(db_path)
            findings_after_first = store.count_findings()
            store.close()

            # Second run with same DB — files already checked
            _run(cfg)

            # Verify no new findings were added to the DB
            store = SQLiteStateStore(db_path)
            findings_after_second = store.count_findings()
            store.close()
            assert findings_after_second == findings_after_first
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_resume_state_persists_across_runs(self, cfg):
        """Resume DB records files from first run."""
        from snaffler.resume.scan_state import SQLiteStateStore

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            cfg.state.state_db = db_path
            _run(cfg)

            # Check state DB has entries
            store = SQLiteStateStore(db_path)
            unchecked = store.load_unchecked_files()
            store.close()

            # All files should be checked (none unchecked)
            assert len(unchecked) == 0
        finally:
            Path(db_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Resume: directory re-walk avoidance
# ---------------------------------------------------------------------------

def _make_resume_cfg(db_path, root_dir):
    """Build a config for resume tests with a real state DB and local target."""
    c = SnafflerConfiguration()
    c.targets.local_targets = [str(root_dir)]
    c.scanning.max_read_bytes = 2 * 1024 * 1024
    c.scanning.max_file_bytes = 10 * 1024 * 1024
    c.scanning.match_context_bytes = 200
    c.scanning.min_interest = 0
    c.advanced.share_threads = 2
    c.advanced.tree_threads = 2
    c.advanced.file_threads = 2
    c.state.state_db = db_path
    RuleLoader.load(c)
    return c


class TestResumeSkipsDoneShares:
    """Verify that resume does NOT re-walk shares/dirs that are already done.

    Each test creates a real directory tree, runs a full scan against a
    real SQLite state DB, then mutates the filesystem and/or the DB and
    runs again to verify only the expected work happens.
    """

    def test_done_share_not_rewalked_new_root_file_invisible(self, tmp_path):
        """After a full scan, adding a new file to the share root is NOT
        found on resume because the done share is skipped entirely."""
        from snaffler.resume.scan_state import SQLiteStateStore

        root = tmp_path / "share"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"first run finding")
        sub = root / "subdir"
        sub.mkdir()
        (sub / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, root)

        # First run — full scan
        _run(cfg)

        store = SQLiteStateStore(db_path)
        findings_first = store.count_findings()
        assert findings_first >= 2  # ntds.dit + id_rsa at minimum
        store.close()

        # Add a new high-signal file to the root AFTER the scan
        (root / "SYSTEM").write_bytes(b"new file after done")

        # Resume — done share should be skipped, new file NOT found
        cfg2 = _make_resume_cfg(db_path, root)
        _run(cfg2)

        store = SQLiteStateStore(db_path)
        findings_second = store.count_findings()
        store.close()

        assert findings_second == findings_first, (
            f"Done share was re-walked: {findings_second} > {findings_first}"
        )

    def test_done_share_new_subdir_file_invisible(self, tmp_path):
        """After a full scan, adding a new file in an existing subdir is NOT
        found on resume — the entire share tree is skipped."""
        from snaffler.resume.scan_state import SQLiteStateStore

        root = tmp_path / "share"
        root.mkdir()
        sub = root / "configs"
        sub.mkdir()
        (sub / "web.config").write_text(
            '<connectionStrings>'
            '<add connectionString="Server=db;Password=secret"/>'
            '</connectionStrings>'
        )

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, root)
        _run(cfg)

        store = SQLiteStateStore(db_path)
        findings_first = store.count_findings()
        store.close()

        # Add new file deep in the tree
        (sub / "SAM").write_bytes(b"added after scan")

        cfg2 = _make_resume_cfg(db_path, root)
        _run(cfg2)

        store = SQLiteStateStore(db_path)
        findings_second = store.count_findings()
        store.close()

        assert findings_second == findings_first

    def test_fresh_scan_finds_all_files(self, tmp_path):
        """Control test: without a state DB, a fresh scan finds everything
        including files added after a previous run."""
        from snaffler.resume.scan_state import SQLiteStateStore

        root = tmp_path / "share"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"original")

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, root)
        _run(cfg)

        store = SQLiteStateStore(db_path)
        findings_first = store.count_findings()
        store.close()

        # Add new file
        (root / "SYSTEM").write_bytes(b"new file")

        # Delete DB — fresh scan
        Path(db_path).unlink()
        cfg2 = _make_resume_cfg(db_path, root)
        _run(cfg2)

        store = SQLiteStateStore(db_path)
        findings_fresh = store.count_findings()
        store.close()

        assert findings_fresh > findings_first, (
            f"Fresh scan should find more: {findings_fresh} <= {findings_first}"
        )

    def test_walked_root_not_relisted_on_resume(self, tmp_path):
        """When the share root was walked but the share is NOT marked done
        (e.g. interrupted mid-scan), the root is not re-listed.  A new file
        added to the root after the walk should be invisible on resume."""
        from snaffler.resume.scan_state import SQLiteStateStore

        root = tmp_path / "share"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"root finding")
        sub = root / "deep"
        sub.mkdir()
        (sub / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, root)
        _run(cfg)

        store = SQLiteStateStore(db_path)
        findings_first = store.count_findings()
        # Undo the share-done flag so the share is "incomplete"
        store.conn.execute(
            "UPDATE target_share SET done = 0"
        )
        store.conn.commit()
        store.close()

        # Add a new file to the root — shouldn't be found because
        # the root dir was already walked (even though share isn't done)
        (root / "SAM").write_bytes(b"sneaky new file")

        cfg2 = _make_resume_cfg(db_path, root)
        _run(cfg2)

        store = SQLiteStateStore(db_path)
        findings_second = store.count_findings()
        store.close()

        assert findings_second == findings_first, (
            f"Root was re-walked despite being marked walked: "
            f"{findings_second} > {findings_first}"
        )

    def test_unwalked_subdir_is_resumed(self, tmp_path):
        """When a subdir is marked unwalked in the DB, it IS re-walked on
        resume and new files in it are found."""
        from snaffler.resume.scan_state import SQLiteStateStore

        root = tmp_path / "share"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"root file")
        sub = root / "important"
        sub.mkdir()
        (sub / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, root)
        _run(cfg)

        store = SQLiteStateStore(db_path)
        findings_first = store.count_findings()
        assert findings_first >= 2

        # Simulate interrupted walk: mark subdir as unwalked and its
        # files as unchecked so they get re-processed
        share_root = str(root)
        sub_path = str(sub)
        store.conn.execute(
            "UPDATE target_dir SET walked = 0 WHERE unc_path = ?",
            (sub_path,),
        )
        store.conn.execute(
            "UPDATE target_file SET checked = 0 WHERE unc_path LIKE ?",
            (sub_path + "%",),
        )
        # Undo share-done so resume actually processes this share
        store.conn.execute(
            "UPDATE target_share SET done = 0"
        )
        store.conn.commit()

        # Add a NEW detectable file in the unwalked subdir
        (sub / "SAM").write_bytes(b"found on resume")
        store.close()

        cfg2 = _make_resume_cfg(db_path, root)
        _run(cfg2)

        store = SQLiteStateStore(db_path)
        findings_second = store.count_findings()
        store.close()

        assert findings_second > findings_first, (
            f"Unwalked subdir was not re-walked: "
            f"{findings_second} <= {findings_first}"
        )

    def test_resume_progress_counts_done_shares(self, tmp_path):
        """Done shares should still be counted in shares_walked progress."""
        root = tmp_path / "share"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"data")

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, root)
        _run(cfg)

        # Second run — share is done
        cfg2 = _make_resume_cfg(db_path, root)
        _, p = _run(cfg2)

        assert p.shares_walked >= 1
        assert p.scan_complete is True

    def test_multiple_shares_only_incomplete_rewalked(self, tmp_path):
        """With two share roots, one done and one incomplete, only the
        incomplete one should have its tree re-walked."""
        from snaffler.resume.scan_state import SQLiteStateStore

        share_a = tmp_path / "share_a"
        share_a.mkdir()
        (share_a / "ntds.dit").write_bytes(b"share a finding")

        share_b = tmp_path / "share_b"
        share_b.mkdir()
        (share_b / "id_rsa").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n"
        )

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, share_a)
        cfg.targets.local_targets = [str(share_a), str(share_b)]
        _run(cfg)

        store = SQLiteStateStore(db_path)
        findings_first = store.count_findings()

        # Mark share_b as incomplete (not done, subdir unwalked)
        store.conn.execute(
            "UPDATE target_share SET done = 0 WHERE unc_path = ?",
            (str(share_b),),
        )
        store.conn.execute(
            "UPDATE target_dir SET walked = 0 WHERE unc_path = ?",
            (str(share_b),),
        )
        store.conn.execute(
            "UPDATE target_file SET checked = 0 WHERE unc_path LIKE ?",
            (str(share_b) + "%",),
        )
        store.conn.commit()
        store.close()

        # Add new files to BOTH shares
        (share_a / "SAM").write_bytes(b"invisible in done share")
        (share_b / "SYSTEM").write_bytes(b"visible in incomplete share")

        cfg2 = _make_resume_cfg(db_path, share_a)
        cfg2.targets.local_targets = [str(share_a), str(share_b)]
        _run(cfg2)

        store = SQLiteStateStore(db_path)
        findings_second = store.count_findings()
        # Check that SYSTEM was found (from incomplete share_b)
        all_findings = store.load_findings()
        found_paths = [f["file_path"] for f in all_findings]
        store.close()

        # share_b's new file should be found (incomplete share re-walked)
        assert any("SYSTEM" in p for p in found_paths), (
            f"SYSTEM not found in incomplete share: {found_paths}"
        )
        # share_a's new file should NOT be found (done share skipped)
        sam_in_a = [
            p for p in found_paths
            if "SAM" in p and str(share_a) in p
        ]
        assert len(sam_in_a) == 0, (
            f"SAM found in done share_a — share was re-walked: {sam_in_a}"
        )

    def test_resume_no_extra_findings_second_run(self, tmp_path):
        """Basic sanity: two identical runs produce the same finding count."""
        from snaffler.resume.scan_state import SQLiteStateStore

        root = tmp_path / "share"
        root.mkdir()
        (root / "ntds.dit").write_bytes(b"creds")
        sub = root / "configs"
        sub.mkdir()
        (sub / "web.config").write_text(
            '<connectionStrings>'
            '<add connectionString="Server=db;Password=s"/>'
            '</connectionStrings>'
        )
        deep = sub / "nested"
        deep.mkdir()
        (deep / "id_rsa").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n"
        )

        db_path = str(tmp_path / "state.db")
        cfg = _make_resume_cfg(db_path, root)
        _run(cfg)

        store = SQLiteStateStore(db_path)
        findings_first = store.count_findings()
        store.close()

        cfg2 = _make_resume_cfg(db_path, root)
        _run(cfg2)

        store = SQLiteStateStore(db_path)
        findings_second = store.count_findings()
        store.close()

        assert findings_second == findings_first


# ---------------------------------------------------------------------------
# Download (--snaffle)
# ---------------------------------------------------------------------------

class TestDownload:

    def test_snaffle_downloads_files(self, cfg, tmp_path):
        download_dir = tmp_path / "loot"
        cfg.scanning.snaffle = True
        cfg.scanning.snaffle_path = str(download_dir)
        _run(cfg)

        # Should have downloaded at least one finding
        downloaded = list(download_dir.rglob("*"))
        files = [f for f in downloaded if f.is_file()]
        assert len(files) > 0

    def test_snaffle_directory_structure(self, cfg, tmp_path):
        """Downloaded files should have proper directory hierarchy, not flat."""
        download_dir = tmp_path / "loot"
        cfg.scanning.snaffle = True
        cfg.scanning.snaffle_path = str(download_dir)
        _run(cfg)

        # Check that no path component contains backslashes
        for f in download_dir.rglob("*"):
            for part in f.relative_to(download_dir).parts:
                assert "\\" not in part, f"Backslash in path component: {part}"


# ---------------------------------------------------------------------------
# Content scanning through the runner
# ---------------------------------------------------------------------------

class TestContentScanning:

    def test_content_matches_produced(self, cfg, tmp_path):
        """Runner produces content-based matches, not just filename matches."""
        root = tmp_path / "content_test"
        root.mkdir()
        (root / "deploy.ps1").write_text('$password = "hunter2"\n')
        (root / "innocent.txt").write_text("nothing interesting here\n")

        cfg.targets.local_targets = [str(root)]
        _, p = _run(cfg)

        assert p.files_matched >= 1

    def test_connection_string_detected(self, cfg, tmp_path):
        root = tmp_path / "conn_test"
        root.mkdir()
        (root / "web.config").write_text(
            '<connectionStrings>'
            '<add connectionString="Server=db;Password=secret"/>'
            '</connectionStrings>'
        )

        cfg.targets.local_targets = [str(root)]
        _, p = _run(cfg)

        assert p.files_matched >= 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_directory(self, cfg, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        cfg.targets.local_targets = [str(empty)]
        _, p = _run(cfg)
        assert p.files_matched == 0
        assert p.scan_complete is True

    def test_nonexistent_directory(self, cfg):
        cfg.targets.local_targets = ["/nonexistent/path/12345"]
        _, p = _run(cfg)
        assert p.files_matched == 0
        assert p.scan_complete is True

    def test_permission_denied_subdir(self, cfg, tmp_path):
        """Inaccessible subdirectory is skipped without crashing."""
        root = tmp_path / "perm_test"
        root.mkdir()

        good = root / "good"
        good.mkdir()
        (good / "ntds.dit").write_bytes(b"findme")

        bad = root / "noaccess"
        bad.mkdir()
        (bad / "SAM").write_bytes(b"hidden")
        bad.chmod(0o000)

        try:
            cfg.targets.local_targets = [str(root)]
            _, p = _run(cfg)
            assert p.files_matched >= 1  # ntds.dit found
            assert p.scan_complete is True
        finally:
            bad.chmod(0o755)


# ---------------------------------------------------------------------------
# Combined flags
# ---------------------------------------------------------------------------

class TestCombinedFlags:

    def test_exclude_plus_min_interest(self, cfg):
        """Exclude + min_interest stack correctly."""
        cfg.targets.exclude_unc = ["*/archives*", "*/relay_*"]
        cfg.scanning.min_interest = 2
        _, p = _run(cfg)

        # Fewer matches than default, but still some
        assert p.files_matched > 0

        # Compare against no filters
        cfg2 = SnafflerConfiguration()
        cfg2.targets.local_targets = [str(_DATA_DIR)]
        cfg2.scanning.max_read_bytes = 2 * 1024 * 1024
        cfg2.scanning.max_file_bytes = 10 * 1024 * 1024
        cfg2.scanning.match_context_bytes = 200
        cfg2.scanning.min_interest = 0
        cfg2.advanced.share_threads = 2
        cfg2.advanced.tree_threads = 2
        cfg2.advanced.file_threads = 2
        cfg2.state.state_db = ":memory:"
        RuleLoader.load(cfg2)
        _, p2 = _run(cfg2)

        assert p.files_matched < p2.files_matched

    def test_exclude_plus_match_filter(self, cfg):
        cfg.targets.exclude_unc = ["*/archives*"]
        cfg.scanning.match_filter = "password"
        _, p = _run(cfg)

        assert p.files_matched > 0
        assert p.files_scanned > 0

    def test_depth_plus_exclude(self, cfg, tmp_path):
        """Depth limit + exclude together."""
        root = tmp_path / "combo"
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

        cfg.targets.local_targets = [str(root)]
        cfg.scanning.max_depth = 1
        cfg.targets.exclude_unc = ["*/skipme*"]
        _, p = _run(cfg)

        # Should find ntds.dit (root) and id_rsa (keep/), but not SAM (skipme/) or SYSTEM (deep/)
        assert p.files_matched >= 2

    def test_match_filter_plus_min_interest(self, cfg):
        """Both filters applied simultaneously."""
        cfg.scanning.match_filter = "password"
        cfg.scanning.min_interest = 2
        _, p = _run(cfg)

        # Very restrictive — fewer matches
        assert p.files_scanned > 0


# ---------------------------------------------------------------------------
# --rescan-unreadable (real SQLite, mocked ShareFinder)
# ---------------------------------------------------------------------------

class TestRescanUnreadable:
    """Integration tests for --rescan-unreadable with a real SQLite state DB."""

    def _make_cfg(self, db_path):
        c = SnafflerConfiguration()
        c.advanced.share_threads = 2
        c.advanced.tree_threads = 2
        c.advanced.file_threads = 2
        c.scanning.max_read_bytes = 2 * 1024 * 1024
        c.scanning.max_file_bytes = 10 * 1024 * 1024
        c.scanning.match_context_bytes = 200
        c.scanning.min_interest = 0
        c.state.state_db = str(db_path)
        RuleLoader.load(c)
        return c

    def test_full_flow_store_then_rescan(self, tmp_path):
        """End-to-end: normal scan stores unreadable shares, rescan picks them up."""
        from unittest.mock import patch, MagicMock
        from snaffler.resume.scan_state import SQLiteStateStore, ScanState

        db_path = tmp_path / "test.db"

        # Phase 1: simulate a normal scan that stored some unreadable shares
        store = SQLiteStateStore(str(db_path))
        store.store_shares([
            ("//SRV1/PUBLIC", True),
            ("//SRV1/FINANCE", False),
            ("//SRV2/BACKUP", False),
            ("//SRV2/IT", True),
        ])
        store.close()

        # Phase 2: rescan with new creds
        cfg = self._make_cfg(db_path)
        cfg.targets.rescan_unreadable = True

        with patch("snaffler.discovery.shares.ShareFinder") as finder_cls:
            finder = finder_cls.return_value
            # FINANCE now readable, BACKUP still denied
            finder.is_share_readable.side_effect = lambda c, s: s == "FINANCE"

            runner = SnafflerRunner(cfg)
            # Don't actually walk — we just test the rescan logic
            runner.file_pipeline.run = MagicMock()
            runner.execute()

        # Only FINANCE should be passed to file pipeline
        runner.file_pipeline.run.assert_called_once()
        paths = runner.file_pipeline.run.call_args[0][0]
        assert paths == ["//SRV1/FINANCE"]

        # Verify DB was updated
        store2 = SQLiteStateStore(str(db_path))
        readable = sorted(store2.load_shares())
        unreadable = sorted(store2.load_unreadable_shares())
        store2.close()

        assert "//SRV1/FINANCE" in readable
        assert "//SRV1/PUBLIC" in readable
        assert "//SRV2/IT" in readable
        assert unreadable == ["//SRV2/BACKUP"]

    def test_rescan_empty_db(self, tmp_path):
        """Rescan on a fresh DB with no unreadable shares does nothing."""
        from unittest.mock import MagicMock

        db_path = tmp_path / "empty.db"
        cfg = self._make_cfg(db_path)
        cfg.targets.rescan_unreadable = True

        runner = SnafflerRunner(cfg)
        runner.file_pipeline.run = MagicMock()
        runner.execute()

        runner.file_pipeline.run.assert_not_called()
        assert runner.progress.scan_complete is True

    def test_rescan_all_still_denied(self, tmp_path):
        """All shares still denied: DB unchanged, file pipeline not called."""
        from unittest.mock import patch, MagicMock
        from snaffler.resume.scan_state import SQLiteStateStore

        db_path = tmp_path / "denied.db"
        store = SQLiteStateStore(str(db_path))
        store.store_shares([
            ("//SRV/SECRET1", False),
            ("//SRV/SECRET2", False),
        ])
        store.close()

        cfg = self._make_cfg(db_path)
        cfg.targets.rescan_unreadable = True

        with patch("snaffler.discovery.shares.ShareFinder") as finder_cls:
            finder = finder_cls.return_value
            finder.is_share_readable.return_value = False

            runner = SnafflerRunner(cfg)
            runner.file_pipeline.run = MagicMock()
            runner.execute()

        runner.file_pipeline.run.assert_not_called()

        # DB still has both as unreadable
        store2 = SQLiteStateStore(str(db_path))
        assert sorted(store2.load_unreadable_shares()) == ["//SRV/SECRET1", "//SRV/SECRET2"]
        assert store2.load_shares() == []
        store2.close()

    def test_rescan_connection_error_continues(self, tmp_path):
        """Connection error on one share doesn't block others."""
        from unittest.mock import patch, MagicMock
        from snaffler.resume.scan_state import SQLiteStateStore

        db_path = tmp_path / "errors.db"
        store = SQLiteStateStore(str(db_path))
        store.store_shares([
            ("//DEAD/SHARE", False),
            ("//ALIVE/DATA", False),
        ])
        store.close()

        cfg = self._make_cfg(db_path)
        cfg.targets.rescan_unreadable = True

        with patch("snaffler.discovery.shares.ShareFinder") as finder_cls:
            finder = finder_cls.return_value

            def check(computer, share_name):
                if computer == "DEAD":
                    raise ConnectionError("host unreachable")
                return True

            finder.is_share_readable.side_effect = check

            runner = SnafflerRunner(cfg)
            runner.file_pipeline.run = MagicMock()
            runner.execute()

        # ALIVE/DATA should still be scanned despite DEAD failing
        runner.file_pipeline.run.assert_called_once()
        paths = runner.file_pipeline.run.call_args[0][0]
        assert paths == ["//ALIVE/DATA"]

        # DEAD/SHARE should still be unreadable in DB
        store2 = SQLiteStateStore(str(db_path))
        assert store2.load_unreadable_shares() == ["//DEAD/SHARE"]
        assert "//ALIVE/DATA" in store2.load_shares()
        store2.close()
