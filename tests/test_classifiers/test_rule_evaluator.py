import re
from unittest.mock import MagicMock

from snaffler.analysis.file_context import FileContext
from snaffler.classifiers.evaluator import RuleEvaluator, RuleDecision
from snaffler.classifiers.rules import MatchLocation, MatchAction


# ---------- helpers ----------

def make_ctx():
    return FileContext(
        unc_path="//HOST/SHARE/secret.txt",
        name="secret.txt",
        ext=".txt",
        size=1337,
    )


def make_rule(
    *,
    location,
    action=MatchAction.SNAFFLE,
    match_return=None,
    match_length=None,
    relay_targets=None,
):
    rule = MagicMock()
    rule.match_location = location
    rule.match_action = action
    rule.match_length = match_length
    rule.relay_targets = relay_targets
    rule.matches.return_value = match_return
    return rule


# ---------- evaluate_file_rule ----------

def test_evaluate_file_rule_path_match():
    ctx = make_ctx()

    rule = make_rule(
        location=MatchLocation.FILE_PATH,
        match_return=re.search("secret", ctx.unc_path),
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert isinstance(decision, RuleDecision)
    assert decision.action == MatchAction.SNAFFLE
    assert decision.match == "secret"


def test_evaluate_file_rule_name_match():
    ctx = make_ctx()

    rule = make_rule(
        location=MatchLocation.FILE_NAME,
        match_return=re.search("secret", ctx.name),
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert decision.match == "secret"


def test_evaluate_file_rule_extension_match():
    ctx = make_ctx()

    rule = make_rule(
        location=MatchLocation.FILE_EXTENSION,
        match_return=".txt",
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert decision.match == ".txt"


def test_evaluate_file_rule_length_match():
    ctx = make_ctx()

    rule = make_rule(
        location=MatchLocation.FILE_LENGTH,
        match_length=1337,
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert decision.match == "size == 1337"


def test_evaluate_file_rule_no_match():
    ctx = make_ctx()

    rule = make_rule(
        location=MatchLocation.FILE_NAME,
        match_return=None,
    )

    ev = RuleEvaluator([rule], [], [])
    decision = ev.evaluate_file_rule(rule, ctx)

    assert decision is None


# ---------- should_discard_postmatch ----------

def test_should_discard_postmatch_true():
    ctx = make_ctx()

    rule = make_rule(
        location=MatchLocation.FILE_PATH,
        action=MatchAction.DISCARD,
        match_return=True,
    )

    ev = RuleEvaluator([], [], [rule])

    assert ev.should_discard_postmatch(ctx) is True


def test_should_discard_postmatch_false():
    ctx = make_ctx()

    rule = make_rule(
        location=MatchLocation.FILE_NAME,
        action=MatchAction.DISCARD,
        match_return=False,
    )

    ev = RuleEvaluator([], [], [rule])

    assert ev.should_discard_postmatch(ctx) is False
