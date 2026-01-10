#!/usr/bin/env python3

import logging
from datetime import datetime
from typing import Optional, List

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.analysis.certificates import CertificateChecker
from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import MatchLocation, MatchAction, Triage
from snaffler.utils.logger import log_file_result
from snaffler.utils.path_utils import parse_unc_path, get_modified_time

logger = logging.getLogger("snaffler")


class FileScanner:
    def __init__(
            self,
            cfg,
            file_accessor: FileAccessor,
            rule_evaluator: RuleEvaluator,
    ):
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
            result.modified.strftime("%Y-%m-%d %H:%M:%S")
            if result.modified
            else None,
        )

        if (
                self.cfg.scanning.snaffle
                and result.size <= self.cfg.scanning.max_file_bytes
        ):
            self.file_accessor.copy_to_local(
                server,
                share,
                smb_path,
                self.cfg.scanning.snaffle_path,
            )

        return result

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

            if not self.file_accessor.can_read(server, share, smb_path):
                return None

            ctx = FileContext(
                unc_path=unc_path,
                name=file_name,
                ext=file_ext,
                size=size,
            )

            content_rule_names: set[str] = set()
            best_result: Optional[FileResult] = None

            # ---------------- File rules
            for rule in self.rule_evaluator.file_rules:
                decision = self.rule_evaluator.evaluate_file_rule(rule, ctx)
                if not decision:
                    continue

                action = decision.action

                if action == MatchAction.DISCARD:
                    return None

                if action == MatchAction.RELAY:
                    if decision.content_rule_names:
                        content_rule_names.update(decision.content_rule_names)
                    continue

                if action == MatchAction.CHECK_FOR_KEYS:
                    cert = self._check_certificate(ctx, server, share, smb_path, modified)
                    if cert:
                        cert = self._finalize_result(
                            cert, server, share, smb_path
                        )
                        best_result = FileResult.pick_best(best_result, cert)
                    continue

                if action != MatchAction.SNAFFLE:
                    continue

                if self.rule_evaluator.should_discard_postmatch(ctx):
                    return None

                result = FileResult(
                    file_path=unc_path,
                    size=size,
                    modified=modified,
                    triage=rule.triage,
                    rule_name=rule.rule_name,
                    match=decision.match,
                )

                result = self._finalize_result(
                    result, server, share, smb_path
                )
                best_result = FileResult.pick_best(best_result, result)

            # ---------------- Content rules
            if size <= self.cfg.scanning.max_read_bytes:
                content_result = self._scan_file_contents(
                    ctx,
                    server,
                    share,
                    smb_path,
                    modified,
                    content_rule_names or None,
                )
                return FileResult.pick_best(best_result, content_result)

            return best_result

        except Exception as e:
            logger.debug(f"Unhandled exception while scanning {unc_path}: {e}")
            return

    def _scan_file_contents(
            self,
            ctx: FileContext,
            server: str,
            share: str,
            smb_path: str,
            modified: datetime,
            content_rules_to_evaluate: Optional[List[str]],
    ) -> Optional[FileResult]:

        data = self.file_accessor.read(server, share, smb_path)
        if not data:
            return None

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="ignore")

        rules = (
            [
                self.rule_evaluator.content_rules_by_name[n]
                for n in content_rules_to_evaluate
                if n in self.rule_evaluator.content_rules_by_name
            ]
            if content_rules_to_evaluate
            else self.rule_evaluator.content_rules
        )

        for rule in rules:
            if rule.match_location != MatchLocation.FILE_CONTENT_AS_STRING:
                continue

            match = rule.matches(text)
            if not match:
                continue

            if self.rule_evaluator.should_discard_postmatch(ctx):
                continue

            start = max(
                0,
                match.start() - self.cfg.scanning.match_context_bytes,
            )
            end = min(
                len(text),
                match.end() + self.cfg.scanning.match_context_bytes,
            )

            result = FileResult(
                file_path=ctx.unc_path,
                size=ctx.size,
                modified=modified,
                triage=rule.triage,
                rule_name=rule.rule_name,
                match=match.group(0),
                context=text[start:end],
            )

            return self._finalize_result(
                result, server, share, smb_path
            )

        return None

    # -------------------------------------------------------------- Certs

    def _check_certificate(
            self,
            ctx: FileContext,
            server: str,
            share: str,
            smb_path: str,
            modified: datetime,
    ) -> Optional[FileResult]:

        data = self.file_accessor.read(server, share, smb_path)
        if not data:
            return None

        reasons = self.cert_checker.check_certificate(
            data, ctx.name
        )
        if not reasons or "HasPrivateKey" not in reasons:
            return None

        return FileResult(
            file_path=ctx.unc_path,
            size=ctx.size,
            modified=modified,
            triage=Triage.RED,
            rule_name="RelayCertByExtension",
            match=ctx.name,
            context=", ".join(reasons),
        )
