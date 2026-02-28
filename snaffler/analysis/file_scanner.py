#!/usr/bin/env python3

import logging
import re
from datetime import datetime
from typing import Optional, List

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.analysis.certificates import CertificateChecker
from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import MatchLocation, MatchAction, Triage
from snaffler.utils.logger import log_file_result
from snaffler.utils.path_utils import parse_unc_path

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
        mf = getattr(cfg.scanning, 'match_filter', None)
        self._match_re = (
            re.compile(mf, re.IGNORECASE)
            if isinstance(mf, str) else None
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

        # --match is purely an output filter — DB persistence and downloads
        # are not affected, only console/file log output is suppressed
        suppress_log = False
        if self._match_re:
            haystack = "\n".join(filter(None, [
                result.file_path, result.rule_name,
                result.match, result.context,
            ]))
            if not self._match_re.search(haystack):
                suppress_log = True

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
            suppress_log=suppress_log,
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

        if suppress_log:
            return None

        return result

    # -------------------------------------------------------------- Scanning

    def scan_file(self, unc_path: str, size: int, mtime_epoch: float) -> Optional[FileResult]:
        try:
            parsed = parse_unc_path(unc_path)
            if not parsed:
                return None

            server, share, smb_path, file_name, file_ext = parsed
            modified = datetime.fromtimestamp(mtime_epoch) if mtime_epoch else None

            ctx = FileContext(
                unc_path=unc_path,
                smb_path=smb_path,
                name=file_name,
                ext=file_ext,
                size=size,
                modified=modified
            )

            content_rule_names: set[str] = set()
            best_result: Optional[FileResult] = None

            logger.debug(f"Evaluating file rules: {unc_path} (size={size})")

            # ---------------- File rules
            for rule in self.rule_evaluator.file_rules:
                decision = self.rule_evaluator.evaluate_file_rule(rule, ctx)
                if not decision:
                    continue

                logger.debug(f"{decision.action.name}: {unc_path}")

                action = decision.action

                if action == MatchAction.DISCARD:
                    return None

                if action == MatchAction.RELAY:
                    if decision.content_rule_names:
                        content_rule_names.update(decision.content_rule_names)
                    continue

                if action == MatchAction.CHECK_FOR_KEYS:
                    if self.rule_evaluator.should_discard_postmatch(ctx):
                        continue
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
                    continue

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

            # Black (level 3) is the maximum severity — skip content scan
            if best_result and best_result.triage == Triage.BLACK:
                return best_result

            # ---------------- Content rules
            if content_rule_names:
                content_rules = sorted(
                    (
                        self.rule_evaluator.content_rules_by_name[n]
                        for n in content_rule_names
                        if n in self.rule_evaluator.content_rules_by_name
                    ),
                    key=lambda r: r.triage.level,
                    reverse=True,
                )
            else:
                content_rules = self.rule_evaluator.content_rules

            if size <= self.cfg.scanning.max_read_bytes:
                logger.debug(f"Scanning file content: {unc_path}")
                content_result = self._scan_file_contents(
                    ctx,
                    server,
                    share,
                    content_rules,
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
            rules,
    ) -> Optional[FileResult]:
        smb_path = ctx.smb_path

        data = self.file_accessor.read(
            server, share, smb_path,
            max_bytes=self.cfg.scanning.max_read_bytes,
        )
        if not data:
            return None

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="ignore")

        best_result: Optional[FileResult] = None

        for rule in rules:
            match = rule.matches(text)
            if not match:
                continue

            if self.rule_evaluator.should_discard_postmatch(ctx):
                continue

            # matches() returns re.Match for regex, str for EXACT
            if isinstance(match, str):
                match_text = match
                pos = text.find(match)
                match_start = pos if pos >= 0 else 0
                match_end = match_start + len(match)
            else:
                match_text = match.group(0)
                match_start = match.start()
                match_end = match.end()

            start = max(0, match_start - self.cfg.scanning.match_context_bytes)
            end = min(len(text), match_end + self.cfg.scanning.match_context_bytes)

            result = FileResult(
                file_path=ctx.unc_path,
                size=ctx.size,
                modified=ctx.modified,
                triage=rule.triage,
                rule_name=rule.rule_name,
                match=match_text,
                context=text[start:end],
            )

            result = self._finalize_result(
                result, server, share, smb_path
            )
            best_result = FileResult.pick_best(best_result, result)

            # Black (level 3) is the maximum severity — nothing can beat it
            if best_result and best_result.triage == Triage.BLACK:
                break

        return best_result

    # -------------------------------------------------------------- Certs

    def _check_certificate(
            self,
            ctx: FileContext,
            server: str,
            share: str,
            smb_path: str,
            modified: datetime,
    ) -> Optional[FileResult]:

        data = self.file_accessor.read(
            server, share, smb_path,
            max_bytes=self.cfg.scanning.max_read_bytes,
        )
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
