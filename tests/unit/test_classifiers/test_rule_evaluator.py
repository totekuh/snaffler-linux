import re
from datetime import datetime

from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.evaluator import RuleEvaluator, RuleDecision
from snaffler.classifiers.rules import MatchLocation, MatchAction


# =============================================================================
# helpers
# =============================================================================

def make_ctx(
        *,
        unc_path="//HOST/SHARE/secret.txt",
        smb_path="\\secret.txt",
        name="secret.txt",
        ext=".txt",
        size=1337,
        modified=None,
):
    return FileContext(
        unc_path=unc_path,
        smb_path=smb_path,
        name=name,
        ext=ext,
        size=size,
        modified=modified,
    )


class DummyRule:
    """
    Minimal real rule implementation.

    This intentionally mirrors the evaluator ↔ rule contract:
    - match_location
    - match_action
    - match_length (for FILE_LENGTH)
    - matches(text) -> re.Match | None
    """

    def __init__(
            self,
            *,
            match_location,
            match_action=MatchAction.SNAFFLE,
            pattern=None,
            match_length=None,
    ):
        self.match_location = match_location
        self.match_action = match_action
        self.match_length = match_length
        self.content_rule_names = None
        self._pattern = re.compile(pattern) if pattern else None

    def matches(self, text):
        if self._pattern:
            return self._pattern.search(text)
        return None


# =============================================================================
# evaluate_file_rule
# =============================================================================

def test_file_path_regex_match():
    ctx = make_ctx(unc_path="//HOST/SHARE/very_secret.txt")

    rule = DummyRule(
        match_location=MatchLocation.FILE_PATH,
        pattern=r"very_secret",
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert isinstance(decision, RuleDecision)
    assert decision.match == "very_secret"
    assert decision.action == MatchAction.SNAFFLE


def test_file_name_regex_match():
    ctx = make_ctx(name="passwords.txt")

    rule = DummyRule(
        match_location=MatchLocation.FILE_NAME,
        pattern=r"password",
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert decision.match == "password"


def test_file_extension_regex_match():
    ctx = make_ctx(ext=".conf")

    rule = DummyRule(
        match_location=MatchLocation.FILE_EXTENSION,
        pattern=r"\.conf",
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert decision.match == ".conf"


def test_file_length_exact_match():
    ctx = make_ctx(size=4096)

    rule = DummyRule(
        match_location=MatchLocation.FILE_LENGTH,
        match_length=4096,
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert decision.match == "size == 4096"


def test_file_length_mismatch():
    ctx = make_ctx(size=1024)

    rule = DummyRule(
        match_location=MatchLocation.FILE_LENGTH,
        match_length=4096,
    )

    ev = RuleEvaluator([rule], [], [])

    assert ev.evaluate_file_rule(rule, ctx) is None


def test_no_match_returns_none():
    ctx = make_ctx(name="innocent.txt")

    rule = DummyRule(
        match_location=MatchLocation.FILE_NAME,
        pattern=r"secret",
    )

    ev = RuleEvaluator([rule], [], [])

    assert ev.evaluate_file_rule(rule, ctx) is None


# =============================================================================
# should_discard_postmatch
# =============================================================================

def test_postmatch_discard_by_path():
    ctx = make_ctx(
        unc_path="//HOST/SHARE/Windows Kits/10/Debuggers/sdk.conf",
        name="sdk.conf",
    )

    rule = DummyRule(
        match_location=MatchLocation.FILE_PATH,
        match_action=MatchAction.DISCARD,
        pattern=r"Windows Kits",
    )

    ev = RuleEvaluator([], [], [rule])

    assert ev.should_discard_postmatch(ctx) is True


def test_postmatch_not_discarded():
    ctx = make_ctx(
        unc_path="//HOST/SHARE/real_secret.txt",
        name="real_secret.txt",
    )

    rule = DummyRule(
        match_location=MatchLocation.FILE_PATH,
        match_action=MatchAction.DISCARD,
        pattern=r"Windows Kits",
    )

    ev = RuleEvaluator([], [], [rule])

    assert ev.should_discard_postmatch(ctx) is False

def test_postmatch_discard_large_file_by_size():
    ctx = make_ctx(
        name="huge_dump.sql",
        size=5 * 1024 * 1024 * 1024,  # 5 GB, clearly stupid to scan
    )

    class SizeDiscardRule:
        match_location = MatchLocation.FILE_LENGTH
        match_action = MatchAction.DISCARD

        def matches(self, _):
            # discard anything >= 1 GB
            return ctx.size >= 1 * 1024 * 1024 * 1024

    rule = SizeDiscardRule()

    ev = RuleEvaluator([], [], [rule])

    assert ev.should_discard_postmatch(ctx) is True
