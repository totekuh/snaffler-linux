#!/usr/bin/env python3

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.analysis.certificates import CertificateChecker
from snaffler.analysis.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import MatchLocation, MatchAction, Triage
from snaffler.utils.logger import log_file_result
from snaffler.utils.path_utils import parse_unc_path, get_modified_time

logger = logging.getLogger("snaffler")


class FileScanner:
    def __init__(self, cfg,
                 file_accessor: FileAccessor,
                 rule_evaluator: RuleEvaluator):
        self.cfg = cfg
        self.file_accessor = file_accessor
        self.rule_evaluator = rule_evaluator

        self.cert_checker = CertificateChecker(
            custom_passwords=cfg.scanning.cert_passwords
        )

    # -------------------------------------------------------------- Results

    def _finalize_result(
            self,
            result: FileResult,
            server: str,
            share: str,
            smb_path: str,
    ) -> Optional[FileResult]:

        if result.triage.below(self.cfg.scanning.min_interest):
            return None

        log_file_result(
            logger,
            result.file_path,
            result.triage.label,
            result.rule_name,
            result.match,
            result.context,
            result.size,
            result.modified.strftime("%Y-%m-%d %H:%M:%S") if result.modified else None,
        )

        if (
                self.cfg.scanning.snaffle
                and result.size <= self.cfg.scanning.max_size_to_snaffle
        ):
            self.file_accessor.copy_to_local(
                server,
                share,
                smb_path,
                self.cfg.scanning.snaffle_path,
            )

        return result

    def _build_result(
            self,
            unc_path: str,
            size: int,
            modified: datetime,
            triage: Triage,
            rule_name: str,
            match: str,
            context: Optional[str] = None,
    ) -> FileResult:

        r = FileResult(unc_path, size, modified)
        r.triage = triage
        r.rule_name = rule_name
        r.match = match
        r.context = context
        return r

    # -------------------------------------------------------------- Scanning

    def scan_file(self, unc_path: str, file_info) -> Optional[FileResult]:
        try:
            parsed = parse_unc_path(unc_path)
            if not parsed:
                return None
            logger.debug(f"Scanning {unc_path}")

            server, share, smb_path, file_name, file_ext = parsed
            size = getattr(file_info, "get_filesize", lambda: 0)()
            modified = get_modified_time(file_info)

            relay_targets = []
            best_result = None

            for rule in self.rule_evaluator.file_rules:
                decision = self.rule_evaluator.evaluate_file_rule(
                    rule,
                    unc_path,
                    file_name,
                    file_ext,
                    size,
                )

                if not decision:
                    continue

                action = decision.action

                if action == MatchAction.DISCARD:
                    return None

                if action == MatchAction.RELAY:
                    relay_targets.extend(decision.relay_targets or [])
                    continue

                if action == MatchAction.CHECK_FOR_KEYS:
                    cert = self._check_certificate(
                        server, share, smb_path, unc_path, size, modified
                    )
                    if cert:
                        cert = self._finalize_result(cert, server, share, smb_path)
                        if cert and not best_result:
                            best_result = cert
                    continue

                if action != MatchAction.SNAFFLE:
                    continue

                if self.rule_evaluator.should_discard(unc_path, file_name):
                    return None

                if not self.file_accessor.can_read(server, share, smb_path):
                    continue

                result = self._build_result(
                    unc_path,
                    size,
                    modified,
                    rule.triage,
                    rule.rule_name,
                    decision.match,
                )

                result = self._finalize_result(result, server, share, smb_path)
                if result and not best_result:
                    best_result = result

            if size <= self.cfg.scanning.max_size_to_grep:
                content_result = self._scan_file_contents(
                    server,
                    share,
                    smb_path,
                    unc_path,
                    size,
                    modified,
                    relay_targets or None,
                )
                return content_result or best_result

            return best_result

        except Exception as e:
            logger.debug(f"Error scanning file {unc_path}: {e}")
            return None

    def _scan_file_contents(
            self,
            server: str,
            share: str,
            smb_path: str,
            unc_path: str,
            size: int,
            modified: datetime,
            relay_rule_names: Optional[list],
    ) -> Optional[FileResult]:

        data = self.file_accessor.read(server, share, smb_path)
        if not data:
            return None

        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode("latin-1", errors="ignore")

        rules = (
            [self.rule_evaluator.content_rules_by_name[n] for n in relay_rule_names if
             n in self.rule_evaluator.content_rules_by_name]
            if relay_rule_names
            else self.rule_evaluator.content_rules
        )

        for rule in rules:
            if rule.match_location != MatchLocation.FILE_CONTENT_AS_STRING:
                continue

            match = rule.matches(text)
            if not match:
                continue

            if self.rule_evaluator.should_discard(unc_path, Path(unc_path).name):
                continue

            start = max(0, match.start() - self.cfg.scanning.match_context_bytes)
            end = min(len(text), match.end() + self.cfg.scanning.match_context_bytes)

            result = self._build_result(
                unc_path,
                size,
                modified,
                rule.triage,
                rule.rule_name,
                match.group(0),
                re.escape(text[start:end]),
            )

            return self._finalize_result(result, server, share, smb_path)

        return None

    # -------------------------------------------------------------- Certs

    def _check_certificate(
            self,
            server: str,
            share: str,
            smb_path: str,
            unc_path: str,
            size: int,
            modified: datetime,
    ) -> Optional[FileResult]:

        data = self.file_accessor.read(server, share, smb_path)
        if not data:
            return None

        reasons = self.cert_checker.check_certificate(data, Path(unc_path).name)
        if not reasons or "HasPrivateKey" not in reasons:
            return None

        return self._build_result(
            unc_path,
            size,
            modified,
            Triage.RED,
            "RelayCertByExtension",
            Path(unc_path).name,
            ", ".join(reasons),
        )
