from pathlib import Path
from datetime import datetime

import pytest

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import (
    EnumerationScope,
    MatchAction,
)

DATA_ROOT = Path(__file__).parents[3] / "data" / "gpp"


@pytest.fixture(scope="session")
def evaluator():
    return RuleEvaluator(
        file_rules=get_default_rules(),
        content_rules=[],
        postmatch_rules=[],
    )


def make_ctx(path: Path) -> FileContext:
    return FileContext(
        unc_path=str(path),
        name=path.name,
        ext=path.suffix.lower(),
        size=path.stat().st_size,
        modified=datetime.fromtimestamp(0),
    )


# GPP XML files that should trigger the relay rule
GPP_RELAY_FILES = [
    "Groups.xml",
    "ScheduledTasks.xml",
    "Services.xml",
    "DataSources.xml",
    "Drives.xml",
    "Printers.xml",
]


@pytest.mark.parametrize("filename", GPP_RELAY_FILES)
def test_gpp_xml_triggers_relay(filename, evaluator):
    path = DATA_ROOT / filename
    assert path.exists(), f"Missing test file: {path}"

    ctx = make_ctx(path)
    hits = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue
        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            hits.append((rule.rule_name, decision.action))

    assert hits, f"No rules matched {filename}"
    assert (
        "KeepGPPCredsByName",
        MatchAction.RELAY,
    ) in hits, f"Expected KeepGPPCredsByName RELAY not triggered for {filename}. Got: {hits}"


def test_gpp_content_rule_matches_cpassword(evaluator):
    """Verify the content rule regex matches cpassword attributes in GPP XML."""
    import re
    content_rules = [r for r in evaluator.file_rules
                     if r.rule_name == "KeepGPPCpasswordContent"]
    # content rules live in the full default rule list
    from snaffler.classifiers.default_rules import get_content_grep_rules
    content_rules = [r for r in get_content_grep_rules()
                     if r.rule_name == "KeepGPPCpasswordContent"]
    assert content_rules, "KeepGPPCpasswordContent rule not found"

    rule = content_rules[0]
    # Read a GPP file and check the regex matches
    groups_xml = (DATA_ROOT / "Groups.xml").read_text()
    matched = False
    for pattern in rule.wordlist:
        if re.search(pattern, groups_xml, re.IGNORECASE):
            matched = True
            break
    assert matched, f"cpassword regex did not match Groups.xml content"


def test_gpp_content_rule_no_match_on_clean_xml(evaluator):
    """Printers.xml has no cpassword — content rule should not match."""
    import re
    from snaffler.classifiers.default_rules import get_content_grep_rules
    content_rules = [r for r in get_content_grep_rules()
                     if r.rule_name == "KeepGPPCpasswordContent"]
    assert content_rules

    rule = content_rules[0]
    printers_xml = (DATA_ROOT / "Printers.xml").read_text()
    matched = False
    for pattern in rule.wordlist:
        if re.search(pattern, printers_xml, re.IGNORECASE):
            matched = True
            break
    assert not matched, "cpassword regex should NOT match Printers.xml (no cpassword)"
