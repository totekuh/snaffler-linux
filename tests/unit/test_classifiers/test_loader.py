from unittest.mock import MagicMock, patch
import pytest

from snaffler.classifiers.loader import RuleLoader
from snaffler.classifiers.rules import EnumerationScope
from snaffler.config.configuration import SnafflerConfiguration


# ---------- helpers ----------

def make_rule(scope):
    r = MagicMock()
    r.enumeration_scope = scope
    return r


def make_cfg(rule_dir=None):
    cfg = SnafflerConfiguration()
    cfg.rules.rule_dir = rule_dir
    return cfg


# ---------- tests ----------

def test_load_default_rules():
    rules = [
        make_rule(EnumerationScope.SHARE_ENUMERATION),
        make_rule(EnumerationScope.DIRECTORY_ENUMERATION),
        make_rule(EnumerationScope.FILE_ENUMERATION),
        make_rule(EnumerationScope.CONTENTS_ENUMERATION),
        make_rule(EnumerationScope.POST_MATCH),
    ]

    cfg = make_cfg()

    with patch(
        "snaffler.classifiers.loader.get_default_rules",
        return_value=rules,
    ):
        RuleLoader.load(cfg)

    assert len(cfg.rules.share) == 1
    assert len(cfg.rules.directory) == 1
    assert len(cfg.rules.file) == 1
    assert len(cfg.rules.content) == 1
    assert len(cfg.rules.postmatch) == 1


def test_load_custom_rules_from_directory():
    rules = [
        make_rule(EnumerationScope.FILE_ENUMERATION),
        make_rule(EnumerationScope.FILE_ENUMERATION),
    ]

    cfg = make_cfg(rule_dir="/tmp/rules")

    with patch(
        "snaffler.classifiers.loader.load_rules_from_directory",
        return_value=rules,
    ):
        RuleLoader.load(cfg)

    assert cfg.rules.file == rules
    assert cfg.rules.share == []
    assert cfg.rules.directory == []
    assert cfg.rules.content == []
    assert cfg.rules.postmatch == []


def test_load_rules_empty_raises():
    cfg = make_cfg()

    with patch(
        "snaffler.classifiers.loader.get_default_rules",
        return_value=[],
    ):
        with pytest.raises(RuntimeError, match="No classification rules loaded"):
            RuleLoader.load(cfg)
