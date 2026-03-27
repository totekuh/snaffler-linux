"""Integration tests: domain user rules produce findings in scanned content."""

import pytest
from unittest.mock import MagicMock

from snaffler.classifiers.loader import build_domain_user_rule
from snaffler.classifiers.rules import Triage
from snaffler.analysis.file_scanner import FileScanner
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.rules import EnumerationScope
from tests.conftest import make_scanner_cfg


class TestDomainUserRuleIntegration:
    """Full FileScanner pipeline with injected domain user rule."""

    @staticmethod
    def _make_scanner(usernames, extra_content_rules=None):
        """Create a FileScanner with a domain user rule + optional extras."""
        user_rule = build_domain_user_rule(usernames)
        content_rules = [user_rule]
        if extra_content_rules:
            content_rules.extend(extra_content_rules)

        cfg = make_scanner_cfg()
        evaluator = RuleEvaluator(
            file_rules=[],
            content_rules=content_rules,
            postmatch_rules=[],
        )
        accessor = MagicMock()
        scanner = FileScanner(cfg=cfg, file_accessor=accessor, rule_evaluator=evaluator)
        return scanner, accessor

    def test_finds_username_in_config(self):
        """Username in a config file is detected as Red finding."""
        scanner, accessor = self._make_scanner(["svc_backup", "admin_sql"])
        accessor.read.return_value = (
            b"[Service]\nRunAs=DOMAIN\\svc_backup\nPassword=secret123"
        )

        result = scanner.scan_file("//server/share/app.config", 100, 0.0)

        assert result is not None
        assert result.triage == Triage.RED
        assert result.rule_name == "DynamicDomainUsers"
        assert "svc_backup" in result.match

    def test_finds_second_username(self):
        """Second username in the list also matches."""
        scanner, accessor = self._make_scanner(["svc_backup", "admin_sql"])
        accessor.read.return_value = b"db_user=admin_sql\ndb_pass=hunter2"

        result = scanner.scan_file("//server/share/db.ini", 50, 0.0)

        assert result is not None
        assert "admin_sql" in result.match

    def test_no_match_in_unrelated_content(self):
        """No match when file content doesn't contain any usernames."""
        scanner, accessor = self._make_scanner(["svc_backup", "admin_sql"])
        accessor.read.return_value = b"[Database]\nHost=localhost\nPort=5432"

        result = scanner.scan_file("//server/share/db.config", 50, 0.0)

        assert result is None

    def test_empty_user_list_raises(self):
        """Empty user list raises ValueError."""
        with pytest.raises(ValueError):
            build_domain_user_rule([])

    def test_coexists_with_existing_content_rules(self):
        """Domain user rule works alongside default content rules."""
        # Get a real content rule from defaults
        all_rules = get_default_rules()
        default_content = [
            r for r in all_rules
            if r.enumeration_scope == EnumerationScope.CONTENTS_ENUMERATION
        ][:3]  # take a few

        scanner, accessor = self._make_scanner(
            ["svc_backup"],
            extra_content_rules=default_content,
        )
        accessor.read.return_value = (
            b"[Service]\nRunAs=DOMAIN\\svc_backup\nPassword=secret"
        )

        result = scanner.scan_file("//server/share/app.config", 100, 0.0)

        # Should find the username (Red severity)
        assert result is not None
        assert result.triage.level >= Triage.RED.level

    def test_match_context_includes_surrounding_text(self):
        """The match context includes text around the username."""
        scanner, accessor = self._make_scanner(["svc_backup"])
        accessor.read.return_value = (
            b"# Config file\nservice_account=svc_backup\npassword=P@ssw0rd!\n"
        )

        result = scanner.scan_file("//server/share/svc.conf", 80, 0.0)

        assert result is not None
        assert result.context is not None
        assert "svc_backup" in result.context

    def test_accessor_not_called_when_no_relay(self):
        """Without file rules triggering RELAY, content rules still fire
        because the scanner falls through to full content evaluation."""
        scanner, accessor = self._make_scanner(["svc_sql"])
        accessor.read.return_value = b"user=svc_sql password=secret"

        result = scanner.scan_file("//server/share/creds.txt", 30, 0.0)

        # File accessor should be called (scanner reads content for all files
        # when there are content rules and no DISCARD)
        accessor.read.assert_called_once()
        assert result is not None

    def test_large_user_list_produces_findings(self):
        """1000 users in the rule still produce correct findings."""
        users = [f"svc_user_{i:04d}" for i in range(1000)]
        scanner, accessor = self._make_scanner(users)
        accessor.read.return_value = b"account=svc_user_0500\npass=secret"

        result = scanner.scan_file("//server/share/config.ini", 40, 0.0)

        assert result is not None
        assert "svc_user_0500" in result.match
