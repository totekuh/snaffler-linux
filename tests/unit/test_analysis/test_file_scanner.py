from datetime import datetime
from unittest.mock import MagicMock, patch

from snaffler.analysis.file_scanner import FileScanner
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator, RuleDecision
from snaffler.classifiers.rules import (
    MatchAction,
    MatchLocation,
    Triage,
)


# ---------------- helpers ----------------

def make_cfg(match_filter=None):
    from tests.conftest import make_scanner_cfg
    return make_scanner_cfg(match_filter=match_filter)


def make_rule(
    action,
    location=MatchLocation.FILE_NAME,
    triage=Triage.GREEN,
    name="TestRule",
):
    rule = MagicMock()
    rule.match_action = action
    rule.match_location = location
    rule.triage = triage
    rule.rule_name = name
    return rule


# ---------------- tests ----------------

def test_scan_file_unreadable_content():
    """When read() returns None (access denied), content scan is skipped gracefully."""
    accessor = MagicMock()
    accessor.read.return_value = None

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ContentRule",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert result is None
    accessor.read.assert_called_once()


def test_scan_file_discard_rule():
    accessor = MagicMock()

    rule = make_rule(action=MatchAction.DISCARD)

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.DISCARD
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert result is None


def test_scan_file_snaffle_rule():
    accessor = MagicMock()

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="SecretRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="secret",
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.rule_name == "SecretRule"
    assert result.triage == Triage.RED


def test_scan_file_check_for_keys():
    accessor = MagicMock()

    accessor.read.return_value = b"CERTDATA"

    rule = make_rule(action=MatchAction.CHECK_FOR_KEYS)

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.CHECK_FOR_KEYS
    )
    evaluator.should_discard_postmatch.return_value = False

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch.object(
        scanner.cert_checker,
        "check_certificate",
        return_value=["HasPrivateKey"],
    ):
        result = scanner.scan_file("//srv/share/cert.pfx", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.triage == Triage.RED
    assert "HasPrivateKey" in result.context


def test_scan_file_content_rule():
    accessor = MagicMock()

    accessor.read.return_value = b"this contains password=123"

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ContentRule",
    )

    rule.matches.return_value = MagicMock(
        start=lambda: 14,
        end=lambda: 22,
        group=lambda _: "password",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.rule_name == "ContentRule"
    assert result.triage == Triage.YELLOW


def test_scan_file_zero_mtime():
    """mtime_epoch=0 is a valid epoch timestamp and should not crash."""
    accessor = MagicMock()

    evaluator = MagicMock()
    evaluator.file_rules = []
    evaluator.content_rules = []

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 0.0)

    # No rules match → None result, but we just verify it doesn't crash
    assert result is None


def test_scan_file_black_triage_skips_content_scan():
    """Black-triage file match should skip content scanning entirely (no read() call)."""
    accessor = MagicMock()

    file_rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.BLACK,
        name="KeepNtdsBlack",
    )

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ContentRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [file_rule]
    evaluator.content_rules = [content_rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="ntds.dit",
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    result = scanner.scan_file("//srv/share/ntds.dit", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.triage == Triage.BLACK
    assert result.rule_name == "KeepNtdsBlack"
    # read() should NOT have been called — content scan was skipped
    accessor.read.assert_not_called()


def test_match_filter_passes_matching_finding():
    """Finding whose path matches --match regex is emitted."""
    accessor = MagicMock()

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="SecretRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="secret",
    )

    scanner = FileScanner(make_cfg(match_filter="SecretRule"), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.rule_name == "SecretRule"


def test_match_filter_blocks_non_matching_finding():
    """Finding that does not match --match regex is suppressed."""
    accessor = MagicMock()

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="SecretRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="secret",
    )

    scanner = FileScanner(make_cfg(match_filter="nomatch_pattern"), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    # --match fully suppresses non-matching findings (returns None)
    assert result is None


def test_match_filter_suppresses_non_matching():
    """--match filter returns None for non-matching findings.
    Downloads are now the pipeline's responsibility, not FileScanner's."""
    accessor = MagicMock()

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="SecretRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="secret",
    )

    cfg = make_cfg(match_filter="nomatch_pattern")
    cfg.scanning.snaffle = True
    cfg.scanning.snaffle_path = "/tmp/loot"

    scanner = FileScanner(cfg, accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    # --match fully suppresses non-matching findings
    assert result is None


def test_match_filter_case_insensitive():
    """--match is case-insensitive: uppercase pattern matches lowercase content."""
    accessor = MagicMock()

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.YELLOW,
        name="PasswordRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="password",
    )

    scanner = FileScanner(make_cfg(match_filter="PASSWORD"), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.rule_name == "PasswordRule"


def test_check_file_cert_plus_relay_sets_can_scan_content():
    """BUG-A: cert/archive branch sets _can_scan_content=True when RELAY rules pending."""
    from snaffler.analysis.file_scanner import FileCheckResult, FileCheckStatus

    accessor = MagicMock()

    cert_rule = make_rule(action=MatchAction.CHECK_FOR_KEYS, name="CertRule")
    relay_rule = make_rule(action=MatchAction.RELAY, name="RelayRule")

    evaluator = MagicMock()
    evaluator.file_rules = [relay_rule, cert_rule]
    evaluator.should_discard_postmatch.return_value = False

    # RELAY fires first, then CHECK_FOR_KEYS
    def side_effect(rule, ctx):
        if rule is relay_rule:
            return RuleDecision(
                action=MatchAction.RELAY,
                content_rule_names=["SomeContentRule"],
            )
        if rule is cert_rule:
            return RuleDecision(action=MatchAction.CHECK_FOR_KEYS)
        return None

    evaluator.evaluate_file_rule.side_effect = side_effect

    scanner = FileScanner(make_cfg(), accessor, evaluator)
    result = scanner.check_file("//srv/share/cert.pfx", 100, 1700000000.0)

    assert isinstance(result, FileCheckResult)
    assert result.status == FileCheckStatus.CHECK_KEYS
    assert result._can_scan_content is True


def test_postmatch_lazy_no_content_match():
    """BUG-B: Postmatch is lazy — only evaluated after first content match.

    A content rule that does NOT match should not be blocked by postmatch.
    When no content rule matches at all, the result should be None (no finding),
    and postmatch should never have been consulted.
    """
    accessor = MagicMock()
    accessor.read.return_value = b"innocent content with nothing sensitive"

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ContentRule",
    )
    # The rule does NOT match the content
    content_rule.matches.return_value = None

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[content_rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    # No content match → None result, postmatch did not block anything
    assert result is None


def test_archive_member_cap():
    """BUG-G: _list_archive_members caps at 10,000 entries."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(10_050):
            zf.writestr(f"file_{i:06d}.txt", "x")
    buf.seek(0)

    members = FileScanner._list_archive_members(".zip", buf)
    assert members is not None
    assert len(members) == 10_000


def test_match_filter_passes_matching_result():
    """When --match filter matches, scan_file returns the result (pipeline handles download)."""
    accessor = MagicMock()

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="SecretRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="secret",
    )

    cfg = make_cfg(match_filter="SecretRule")
    cfg.scanning.snaffle = True
    cfg.scanning.snaffle_path = "/tmp/loot"

    scanner = FileScanner(cfg, accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    # Finding matches the filter — result is returned
    assert result is not None
    assert result.rule_name == "SecretRule"


def test_match_filter_none_passes_all():
    """When match_filter is None, all findings are emitted."""
    accessor = MagicMock()

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.GREEN,
        name="AnyRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="data",
    )

    scanner = FileScanner(make_cfg(match_filter=None), accessor, evaluator)

    result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.rule_name == "AnyRule"
