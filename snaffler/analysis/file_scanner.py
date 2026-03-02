#!/usr/bin/env python3

import io
import logging
import os
import re
import zipfile
from datetime import datetime
from typing import Optional, List

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.analysis.certificates import CertificateChecker
from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import MatchLocation, MatchAction, Triage
from snaffler.utils.logger import log_file_result

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
            download_path: str,
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
                download_path,
                self.cfg.scanning.snaffle_path,
            )

        if suppress_log:
            return None

        return result

    # -------------------------------------------------------------- Scanning

    def scan_file(self, file_path: str, size: int, mtime_epoch: float) -> Optional[FileResult]:
        try:
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1]
            modified = datetime.fromtimestamp(mtime_epoch) if mtime_epoch else None

            ctx = FileContext(
                unc_path=file_path,
                name=file_name,
                ext=file_ext,
                size=size,
                modified=modified
            )

            content_rule_names: set[str] = set()
            best_result: Optional[FileResult] = None

            logger.debug(f"Evaluating file rules: {file_path} (size={size})")

            # ---------------- File rules
            for rule in self.rule_evaluator.file_rules:
                decision = self.rule_evaluator.evaluate_file_rule(rule, ctx)
                if not decision:
                    continue

                logger.debug(f"{decision.action.name}: {file_path}")

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
                    cert = self._check_certificate(ctx, modified)
                    if cert:
                        cert = self._finalize_result(cert, file_path)
                        best_result = FileResult.pick_best(best_result, cert)
                    continue

                if action == MatchAction.ENTER_ARCHIVE:
                    if size <= self.cfg.scanning.max_read_bytes:
                        archive_result = self._peek_archive(ctx)
                        best_result = FileResult.pick_best(
                            best_result, archive_result
                        )
                    continue

                if action != MatchAction.SNAFFLE:
                    continue

                if self.rule_evaluator.should_discard_postmatch(ctx):
                    continue

                result = FileResult(
                    file_path=file_path,
                    size=size,
                    modified=modified,
                    triage=rule.triage,
                    rule_name=rule.rule_name,
                    match=decision.match,
                )

                result = self._finalize_result(result, file_path)
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
                logger.debug(f"Scanning file content: {file_path}")
                content_result = self._scan_file_contents(ctx, content_rules)
                return FileResult.pick_best(best_result, content_result)

            return best_result

        except Exception as e:
            logger.debug(f"Unhandled exception while scanning {file_path}: {e}")
            return

    def _scan_file_contents(
            self,
            ctx: FileContext,
            rules,
    ) -> Optional[FileResult]:

        data = self.file_accessor.read(
            ctx.unc_path,
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

            result = self._finalize_result(result, ctx.unc_path)
            best_result = FileResult.pick_best(best_result, result)

            # Black (level 3) is the maximum severity — nothing can beat it
            if best_result and best_result.triage == Triage.BLACK:
                break

        return best_result

    # -------------------------------------------------------------- Archives

    def _peek_archive(
            self,
            ctx: FileContext,
    ) -> Optional[FileResult]:
        """List filenames inside an archive and evaluate file rules against them."""
        try:
            data = self.file_accessor.read(
                ctx.unc_path,
                max_bytes=self.cfg.scanning.max_read_bytes,
            )
            if not data:
                return None

            bio = io.BytesIO(data)
            members = self._list_archive_members(ctx.ext, bio)
            if not members:
                return None

            best_result: Optional[FileResult] = None
            for member_name, member_size in members:
                basename = os.path.basename(member_name)
                member_ext = os.path.splitext(basename)[1].lower()
                member_unc = f"{ctx.unc_path}\u2192{member_name}"

                member_ctx = FileContext(
                    unc_path=member_unc,
                    name=basename,
                    ext=member_ext,
                    size=member_size,
                    modified=ctx.modified,
                )

                for rule in self.rule_evaluator.file_rules:
                    decision = self.rule_evaluator.evaluate_file_rule(
                        rule, member_ctx
                    )
                    if not decision:
                        continue

                    action = decision.action
                    if action == MatchAction.DISCARD:
                        break
                    if action != MatchAction.SNAFFLE:
                        continue

                    if self.rule_evaluator.should_discard_postmatch(member_ctx):
                        continue

                    result = FileResult(
                        file_path=member_unc,
                        size=member_size,
                        modified=ctx.modified,
                        triage=rule.triage,
                        rule_name=rule.rule_name,
                        match=decision.match,
                    )
                    # Download the archive itself, not the member
                    result = self._finalize_result(result, ctx.unc_path)
                    best_result = FileResult.pick_best(best_result, result)

                    if best_result and best_result.triage == Triage.BLACK:
                        return best_result

            return best_result
        except Exception as e:
            logger.debug(
                f"Archive peek failed for {ctx.unc_path}: {e}"
            )
            return None

    @staticmethod
    def _list_archive_members(
            ext: str, bio: io.BytesIO
    ) -> Optional[List[tuple]]:
        """Return list of (name, size) tuples for archive members."""
        ext_lower = ext.lower()

        if ext_lower == ".zip":
            try:
                with zipfile.ZipFile(bio) as zf:
                    return [
                        (info.filename, info.file_size)
                        for info in zf.infolist()
                        if not info.is_dir()
                    ]
            except (zipfile.BadZipFile, Exception):
                return None

        if ext_lower == ".7z":
            try:
                import py7zr
            except ImportError:
                logger.warning(
                    "py7zr not installed — skipping 7z archive peek. "
                    "Install with: pip install snaffler-ng[7z]"
                )
                return None
            try:
                with py7zr.SevenZipFile(bio, mode="r") as sz:
                    return [
                        (entry.filename, entry.uncompressed)
                        for entry in sz.list()
                        if not entry.is_directory
                    ]
            except Exception:
                return None

        if ext_lower == ".rar":
            try:
                import rarfile as _rarfile
            except ImportError:
                logger.warning(
                    "rarfile not installed — skipping RAR archive peek. "
                    "Install with: pip install snaffler-ng[rar]"
                )
                return None
            try:
                with _rarfile.RarFile(bio) as rf:
                    return [
                        (info.filename, info.file_size)
                        for info in rf.infolist()
                        if not info.is_dir()
                    ]
            except Exception:
                return None

        return None

    # -------------------------------------------------------------- Certs

    def _check_certificate(
            self,
            ctx: FileContext,
            modified: datetime,
    ) -> Optional[FileResult]:

        data = self.file_accessor.read(
            ctx.unc_path,
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
