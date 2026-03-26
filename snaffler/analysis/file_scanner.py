#!/usr/bin/env python3

import io
import logging
import os
import re
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List

from snaffler.analysis.certificates import CertificateChecker
from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import MatchLocation, MatchAction, Triage
from snaffler.utils.fatal import check_fatal_os_error

logger = logging.getLogger("snaffler")


class FileCheckStatus(Enum):
    """Outcome of a metadata-only file check."""
    DISCARD = "discard"
    SNAFFLE = "snaffle"
    NEEDS_CONTENT = "needs_content"
    CHECK_KEYS = "check_keys"
    PEEK_ARCHIVE = "peek_archive"


@dataclass
class FileCheckResult:
    """Result of :meth:`FileScanner.check_file`.

    For ``SNAFFLE`` status the finding is in *result*.
    For ``NEEDS_CONTENT`` / ``CHECK_KEYS`` / ``PEEK_ARCHIVE`` the caller
    should fetch bytes and call :meth:`FileScanner.scan_with_data`, passing
    this object as *prior* to avoid re-evaluating file rules.
    """
    status: FileCheckStatus
    result: Optional[FileResult] = None
    content_rule_names: list = field(default_factory=list)
    # -- internal state for Phase 2 (underscore = not part of public API) --
    _ctx: Optional[FileContext] = None
    _best_result: Optional[FileResult] = None
    _needs_cert_check: bool = False
    _needs_archive_peek: bool = False
    _can_scan_content: bool = False


class FileScanner:
    def __init__(
            self,
            cfg,
            file_accessor=None,
            rule_evaluator: RuleEvaluator = None,
    ):
        self.cfg = cfg
        self.file_accessor = file_accessor
        self.rule_evaluator = rule_evaluator

        self.cert_checker = CertificateChecker(
            custom_passwords=cfg.scanning.cert_passwords
        )
        mf = getattr(cfg.scanning, 'match_filter', None)
        self._match_re = None
        if isinstance(mf, str):
            try:
                self._match_re = re.compile(mf, re.IGNORECASE)
            except re.error as e:
                logger.error(f"Invalid --match regex '{mf}': {e}")
                raise SystemExit(1)
        self._max_read_bytes = cfg.scanning.max_read_bytes
        self._match_context_bytes = cfg.scanning.match_context_bytes

    # -------------------------------------------------------------- Results

    def _filter_result(
            self,
            result: FileResult,
    ) -> Optional[FileResult]:
        """Apply min_interest and match_filter to a result. Pure filter, no side effects."""
        if result.triage.below(self.cfg.scanning.min_interest):
            return None

        if self._match_re:
            haystack = "\n".join(filter(None, [
                result.file_path, result.rule_name,
                result.match, result.context,
            ]))
            if not self._match_re.search(haystack):
                return None

        return result

    # -------------------------------------------------------------- Phase 1

    def check_file(self, file_path: str, size: int, mtime_epoch: float) -> FileCheckResult:
        """Phase 1 — evaluate file rules only (zero I/O).

        Returns a :class:`FileCheckResult` whose *status* tells the caller
        what to do next.
        """
        ctx = FileContext.from_path(file_path, size, mtime_epoch)

        content_rule_names: set = set()
        best_result: Optional[FileResult] = None
        needs_cert_check = False
        needs_archive_peek = False
        relay_fired = False

        logger.debug(f"Evaluating file rules: {file_path} (size={size})")

        for rule in self.rule_evaluator.file_rules:
            decision = self.rule_evaluator.evaluate_file_rule(rule, ctx)
            if not decision:
                continue

            logger.debug(f"{decision.action.name}: {file_path}")

            action = decision.action

            if action == MatchAction.DISCARD:
                return FileCheckResult(status=FileCheckStatus.DISCARD)

            if action == MatchAction.RELAY:
                relay_fired = True
                if decision.content_rule_names:
                    content_rule_names.update(decision.content_rule_names)
                continue

            if action == MatchAction.CHECK_FOR_KEYS:
                if not self.rule_evaluator.should_discard_postmatch(ctx):
                    needs_cert_check = True
                continue

            if action == MatchAction.ENTER_ARCHIVE:
                if size <= self._max_read_bytes:
                    if not self.rule_evaluator.should_discard_postmatch(ctx):
                        needs_archive_peek = True
                else:
                    logger.debug(
                        f"Skipping archive peek for {file_path}: "
                        f"size {size} > max {self._max_read_bytes}"
                    )
                continue

            if action != MatchAction.SNAFFLE:
                continue

            if self.rule_evaluator.should_discard_postmatch(ctx):
                continue

            result = FileResult(
                file_path=file_path,
                size=size,
                modified=ctx.modified,
                triage=rule.triage,
                rule_name=rule.rule_name,
                match=decision.match,
            )
            best_result = FileResult.pick_best(best_result, result)

        # Black is max severity — no need for content scan
        if best_result and best_result.triage == Triage.BLACK:
            return FileCheckResult(
                status=FileCheckStatus.SNAFFLE,
                result=best_result,
                _ctx=ctx,
                _best_result=best_result,
            )

        # Determine what Phase 2 needs (cert + archive can coexist with content)
        if needs_cert_check or needs_archive_peek:
            can_content = (relay_fired or bool(content_rule_names)) and size <= self._max_read_bytes
            status = (FileCheckStatus.CHECK_KEYS if needs_cert_check
                      else FileCheckStatus.PEEK_ARCHIVE)
            return FileCheckResult(
                status=status,
                content_rule_names=sorted(content_rule_names) if can_content else [],
                _ctx=ctx,
                _best_result=best_result,
                _needs_cert_check=needs_cert_check,
                _needs_archive_peek=needs_archive_peek,
                _can_scan_content=can_content,
            )

        # Content scan needed: RELAY fired, targeted content rules exist,
        # or no file-rule SNAFFLE found
        if relay_fired or content_rule_names or not best_result:
            if size <= self._max_read_bytes:
                return FileCheckResult(
                    status=FileCheckStatus.NEEDS_CONTENT,
                    content_rule_names=sorted(content_rule_names),
                    _ctx=ctx,
                    _best_result=best_result,
                    _can_scan_content=True,
                )

        if best_result:
            return FileCheckResult(
                status=FileCheckStatus.SNAFFLE,
                result=best_result,
                _ctx=ctx,
                _best_result=best_result,
            )

        return FileCheckResult(status=FileCheckStatus.DISCARD)

    # -------------------------------------------------------------- Phase 2

    def scan_with_data(self, data: bytes, prior: FileCheckResult) -> Optional[FileResult]:
        """Phase 2 — run cert/archive/content checks using raw data.

        Returns the best unfiltered :class:`FileResult`, or ``None``.
        Does NOT apply ``_finalize_result`` (min_interest, match_filter,
        logging, downloads) — that is the caller's responsibility.
        """
        ctx = prior._ctx
        best_result = prior._best_result

        if prior._needs_cert_check:
            cert = self._evaluate_certificate(ctx, data)
            best_result = FileResult.pick_best(best_result, cert)

        if prior._needs_archive_peek:
            archive = self._evaluate_archive(ctx, data)
            best_result = FileResult.pick_best(best_result, archive)

        if prior._can_scan_content:
            # Select content rules
            targeted_names = set(prior.content_rule_names)
            if targeted_names:
                content_rules = sorted(
                    (
                        self.rule_evaluator.content_rules_by_name[n]
                        for n in targeted_names
                        if n in self.rule_evaluator.content_rules_by_name
                    ),
                    key=lambda r: r.triage.level,
                    reverse=True,
                )
            else:
                content_rules = self.rule_evaluator.content_rules

            content = self._evaluate_content(ctx, data, content_rules)
            best_result = FileResult.pick_best(best_result, content)

        return best_result

    # -------------------------------------------------------------- Scanning (composed)

    def scan_file(self, file_path: str, size: int, mtime_epoch: float) -> Optional[FileResult]:
        """Full scan: check_file → optional I/O → scan_with_data → filter.

        This is the main entry point used by FilePipeline.
        Returns a filtered FileResult or None. No logging or download
        side effects — those are the caller's responsibility.
        """
        try:
            check = self.check_file(file_path, size, mtime_epoch)

            if check.status == FileCheckStatus.DISCARD:
                return None

            if check.status == FileCheckStatus.SNAFFLE:
                return self._filter_result(check.result)

            # Phase 2 requires data — read it
            if self.file_accessor is None:
                if check._best_result:
                    return self._filter_result(check._best_result)
                return None

            data = self.file_accessor.read(
                file_path,
                max_bytes=self._max_read_bytes,
            )
            if not data:
                # Access denied or empty — filter whatever we have from Phase 1
                if check._best_result:
                    return self._filter_result(check._best_result)
                return None

            result = self.scan_with_data(data, check)
            if result:
                return self._filter_result(result)
            return None

        except Exception as e:
            check_fatal_os_error(e)
            logger.debug(f"Unhandled exception while scanning {file_path}: {e}")
            return

    # -------------------------------------------------------------- Pure evaluation (no I/O)

    def _evaluate_content(
            self,
            ctx: FileContext,
            data: bytes,
            content_rules,
    ) -> Optional[FileResult]:
        """Evaluate content rules against raw data. No I/O, no finalization."""
        if not data:
            return None

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="ignore")

        best_result: Optional[FileResult] = None

        # Cache postmatch result — invariant within a file, evaluated lazily
        postmatch_checked = False
        postmatch_discard = False

        for rule in content_rules:
            match = rule.matches(text)
            if not match:
                continue

            # Evaluate postmatch once, after the first content match
            if not postmatch_checked:
                postmatch_checked = True
                postmatch_discard = self.rule_evaluator.should_discard_postmatch(ctx)
            if postmatch_discard:
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

            start = max(0, match_start - self._match_context_bytes)
            end = min(len(text), match_end + self._match_context_bytes)

            result = FileResult(
                file_path=ctx.unc_path,
                size=ctx.size,
                modified=ctx.modified,
                triage=rule.triage,
                rule_name=rule.rule_name,
                match=match_text,
                context=text[start:end],
            )

            best_result = FileResult.pick_best(best_result, result)

            # Black (level 3) is the maximum severity — nothing can beat it
            if best_result and best_result.triage == Triage.BLACK:
                break

        return best_result

    # -------------------------------------------------------------- Archives

    def _evaluate_archive(
            self,
            ctx: FileContext,
            data: bytes,
    ) -> Optional[FileResult]:
        """Evaluate archive members against file rules. No I/O, no finalization."""
        try:
            with io.BytesIO(data) as bio:
                members = self._list_archive_members(ctx.ext, bio)
            if not members:
                return None

            best_result: Optional[FileResult] = None
            for member_name, member_size in members:
                # Normalize backslash paths (Windows-created archives)
                member_name = member_name.replace("\\", "/")
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
                    best_result = FileResult.pick_best(best_result, result)

                    if best_result and best_result.triage == Triage.BLACK:
                        return best_result

            return best_result
        except Exception as e:
            logger.debug(
                f"Archive peek failed for {ctx.unc_path}: {e}"
            )
            return None

    _MAX_ARCHIVE_MEMBERS = 10_000

    @staticmethod
    def _list_archive_members(
            ext: str, bio: io.BytesIO
    ) -> Optional[List[tuple]]:
        """Return list of (name, size) tuples for archive members."""
        ext_lower = ext.lower()

        cap = FileScanner._MAX_ARCHIVE_MEMBERS

        if ext_lower == ".zip":
            try:
                with zipfile.ZipFile(bio) as zf:
                    members = []
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        members.append((info.filename, info.file_size))
                        if len(members) >= cap:
                            break
                    return members
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
                    members = []
                    for entry in sz.list():
                        if entry.is_directory:
                            continue
                        members.append((entry.filename, entry.uncompressed or 0))
                        if len(members) >= cap:
                            break
                    return members
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
                    members = []
                    for info in rf.infolist():
                        if info.is_dir():
                            continue
                        members.append((info.filename, info.file_size))
                        if len(members) >= cap:
                            break
                    return members
            except Exception:
                return None

        return None

    # -------------------------------------------------------------- Certs

    def _evaluate_certificate(
            self,
            ctx: FileContext,
            data: bytes,
    ) -> Optional[FileResult]:
        """Evaluate certificate data for private keys. No I/O, no finalization."""
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
            modified=ctx.modified,
            triage=Triage.RED,
            rule_name="RelayCertByExtension",
            match=ctx.name,
            context=", ".join(reasons),
        )
