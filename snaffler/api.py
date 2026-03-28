"""
Public library API for snaffler's classification engine.

Provides a standalone facade that evaluates files against snaffler's rule set
without requiring SMB transport, threads, or a full SnafflerConfiguration.
Designed for C2 integration where a beacon enumerates a local filesystem and
the server runs classification.

Usage::

    from snaffler import Snaffler

    s = Snaffler()
    for finding in s.walk("/mnt/share"):
        print(f"[{finding.triage.label}] {finding.file_path}")

Low-level two-phase API::

    from snaffler import Snaffler, FileCheckStatus

    s = Snaffler()
    check = s.check_file("/path/to/web.config", size=2048, mtime_epoch=1700000000)

    if check.status == FileCheckStatus.NEEDS_CONTENT:
        data = open("/path/to/web.config", "rb").read()
        finding = s.scan_content(data, prior=check)
"""

import logging
import re
from types import SimpleNamespace
from typing import Generator, List, Optional

from snaffler.analysis.file_scanner import (
    FileCheckResult,
    FileCheckStatus,
    FileScanner,
)
from snaffler.analysis.model.file_context import FileContext
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import (
    ClassifierRule,
    EnumerationScope,
    Triage,
    load_rules_from_directory,
)
from snaffler.config.configuration import DEFAULT_CERT_PASSWORDS
from snaffler.discovery.tree import TreeWalker, should_scan_directory
from snaffler.utils.fatal import check_fatal_os_error

logger = logging.getLogger("snaffler")

_DEFAULT_MAX_READ_BYTES = 2 * 1024 * 1024  # 2 MB
_DEFAULT_MATCH_CONTEXT_BYTES = 200


class Snaffler:
    """Standalone classification engine — no transport, no threads.

    Thread-safe after construction (all mutable state is set in ``__init__``
    and never modified afterward).

    Uses the same classification code (``FileScanner``, ``RuleEvaluator``,
    ``TreeWalker._should_scan_directory``) as the CLI pipeline — both
    branches share identical scanning and filtering logic.

    Parameters:
        walker: Directory walker implementing the ``TreeWalker`` ABC, or any
            duck-typed object with a ``walk_directory(path, on_file, on_dir,
            cancel)`` method. Defaults to :class:`LocalTreeWalker`.
        reader: File reader implementing the ``FileAccessor`` ABC, or any
            duck-typed object with a ``read(path, max_bytes)`` method.
            Defaults to :class:`LocalFileAccessor`.
        rule_dir: Path to directory of custom TOML rule files. Uses built-in
            rules if not provided.
        min_interest: Minimum triage severity level (0=Green .. 3=Black).
        max_read_bytes: Maximum bytes to read for content scanning.
        match_context_bytes: Bytes of context around content matches.
        cert_passwords: Passwords to try when parsing PKCS12 certificates.
            Defaults to the same 17-password list used by the CLI.
        exclude_unc: Glob patterns for directories to skip.
        match_filter: Regex to filter findings (case-insensitive).
        max_depth: Maximum directory recursion depth (None = unlimited).
    """

    def __init__(
        self,
        walker=None,
        reader=None,
        rule_dir: Optional[str] = None,
        min_interest: int = 0,
        max_read_bytes: int = _DEFAULT_MAX_READ_BYTES,
        match_context_bytes: int = _DEFAULT_MATCH_CONTEXT_BYTES,
        cert_passwords: Optional[List[str]] = None,
        exclude_unc: Optional[List[str]] = None,
        match_filter: Optional[str] = None,
        max_depth: Optional[int] = None,
    ):
        # ---- load rules (before walker, so we can pass dir_rules) ----
        if rule_dir:
            rules = load_rules_from_directory(rule_dir)
        else:
            rules = get_default_rules()
        if not rules:
            raise RuntimeError("No classification rules loaded")

        dir_rules: List[ClassifierRule] = [
            r for r in rules
            if r.enumeration_scope == EnumerationScope.DIRECTORY_ENUMERATION
        ]
        file_rules = [
            r for r in rules
            if r.enumeration_scope == EnumerationScope.FILE_ENUMERATION
        ]
        content_rules = [
            r for r in rules
            if r.enumeration_scope == EnumerationScope.CONTENTS_ENUMERATION
        ]
        postmatch_rules = [
            r for r in rules
            if r.enumeration_scope == EnumerationScope.POST_MATCH
        ]

        # ---- transport (lazy imports to avoid hard dependency) ----
        _exclude = exclude_unc or []

        if walker is None:
            from snaffler.discovery.local_tree_walker import LocalTreeWalker
            walker = LocalTreeWalker(
                dir_rules=dir_rules,
                exclude_unc=_exclude,
            )
        if reader is None:
            from snaffler.accessors.local_file_accessor import LocalFileAccessor
            reader = LocalFileAccessor()

        self._walker = walker
        self._reader = reader
        self._max_read_bytes = max_read_bytes
        self._max_depth = max_depth

        # ---- shared FileScanner (same as CLI pipeline uses) ----
        evaluator = RuleEvaluator(file_rules, content_rules, postmatch_rules)

        # Use same cert_passwords default as the CLI
        _cert_passwords = cert_passwords if cert_passwords is not None else list(DEFAULT_CERT_PASSWORDS)

        cfg = SimpleNamespace(
            scanning=SimpleNamespace(
                min_interest=min_interest,
                max_read_bytes=max_read_bytes,
                max_file_bytes=max_read_bytes,
                match_context_bytes=match_context_bytes,
                cert_passwords=_cert_passwords,
                snaffle=False,
                snaffle_path=None,
                match_filter=None,  # output filtering done by _apply_filters
            ),
        )

        self._scanner = FileScanner(
            cfg,
            file_accessor=None,
            rule_evaluator=evaluator,
        )

        # ---- output filters ----
        # Keep dir_rules/exclude for check_dir fallback (duck-typed walkers)
        self._dir_rules = dir_rules
        self._exclude_unc = _exclude
        self._min_interest = min_interest
        self._match_re = (
            re.compile(match_filter, re.IGNORECASE)
            if match_filter else None
        )

    # ------------------------------------------------------------------ walk

    def walk(self, root_dir: str, cancel=None) -> Generator[FileResult, None, None]:
        """Walk a directory tree and yield findings.

        Single-threaded, depth-first traversal. Uses the configured walker
        for directory listing and reader for file content.

        Directory filtering (exclude_unc globs + DISCARD rules) is applied
        by the walker's ``_should_scan_directory()`` when the walker is a
        :class:`TreeWalker` subclass, or by :meth:`check_dir` for duck-typed
        walkers.

        Args:
            root_dir: Root directory to start walking from.
            cancel: Optional threading.Event for cooperative cancellation.
        """
        # Stack entries: (path, depth)
        stack = [(root_dir, 0)]
        _is_tree_walker = isinstance(self._walker, TreeWalker)

        while stack:
            if cancel and cancel.is_set():
                return

            dir_path, depth = stack.pop()

            # Dir filtering: TreeWalker subclasses already pre-filter
            # subdirs inside walk_directory().  For duck-typed walkers,
            # check every dir.  Never filter depth 0 — the root was
            # explicitly requested by the caller.
            if not _is_tree_walker and depth > 0:
                if not self._check_dir(dir_path):
                    continue

            files = []
            subdirs_from_cb = []

            def _on_file(path, size, mtime):
                files.append((path, size, mtime))

            def _on_dir(path):
                subdirs_from_cb.append(path)

            try:
                subdirs = self._walker.walk_directory(
                    dir_path, on_file=_on_file, on_dir=_on_dir,
                    cancel=cancel,
                )
                # Use return value if provided, fall back to on_dir callback
                subdirs = subdirs if subdirs is not None else subdirs_from_cb
            except Exception as e:
                check_fatal_os_error(e)
                logger.debug(f"Error walking {dir_path}: {e}")
                continue

            # Push subdirs — reversed so leftmost is processed first.
            # For TreeWalker subclasses, _should_scan_directory() already
            # ran inside walk_directory(), so subdirs are pre-filtered.
            # For duck-typed walkers, _check_dir() runs at pop time.
            if self._max_depth is None or depth < self._max_depth:
                stack.extend(
                    (d, depth + 1) for d in reversed(subdirs)
                )

            # Classify each file
            for file_path, size, mtime_epoch in files:
                finding = self._scan_one(file_path, size, mtime_epoch)
                if finding is not None:
                    yield finding

    def _scan_one(
        self, file_path: str, size: int, mtime_epoch: float,
    ) -> Optional[FileResult]:
        """Scan a single file: check_file -> optional read -> classify -> filter."""
        try:
            check = self._scanner.check_file(file_path, size, mtime_epoch)

            if check.status == FileCheckStatus.DISCARD:
                return None

            if check.status == FileCheckStatus.SNAFFLE:
                return self._apply_filters(check.result)

            # Phase 2: needs data
            data = self._reader.read(file_path, max_bytes=self._max_read_bytes)
            if not data:
                if check._best_result:
                    return self._apply_filters(check._best_result)
                return None

            result = self._scanner.scan_with_data(data, check)
            return self._apply_filters(result)
        except Exception as e:
            check_fatal_os_error(e)
            logger.warning(f"Error scanning {file_path}: {e}")
            return None

    # ------------------------------------------------------------------ dirs

    def check_dir(self, dir_path: str) -> bool:
        """Should this directory be walked?

        Returns ``False`` if the path matches an exclusion glob or a
        directory DISCARD rule, ``True`` otherwise.

        Delegates to ``TreeWalker._should_scan_directory()`` when the
        walker is a :class:`TreeWalker` subclass — same code path as the
        CLI pipeline. Falls back to equivalent inline logic for duck-typed
        walkers.
        """
        return self._check_dir(dir_path)

    def _check_dir(self, dir_path: str) -> bool:
        """Internal dir check — uses walker's shared logic when available."""
        if isinstance(self._walker, TreeWalker):
            return self._walker._should_scan_directory(dir_path)

        # Fallback for duck-typed walkers that don't extend TreeWalker:
        # use the same shared function from tree.py.
        return should_scan_directory(
            dir_path, self._dir_rules, self._exclude_unc,
        )

    # ------------------------------------------------------------------ files

    def check_file(
        self,
        file_path: str,
        size: int,
        mtime_epoch: float,
    ) -> FileCheckResult:
        """Phase 1 — evaluate file rules only (zero I/O).

        Returns a :class:`FileCheckResult` whose *status* tells the caller
        what to do next.
        """
        return self._scanner.check_file(file_path, size, mtime_epoch)

    # ------------------------------------------------------------------ content

    def scan_content(
        self,
        data: bytes,
        prior: Optional[FileCheckResult] = None,
        file_path: Optional[str] = None,
        size: Optional[int] = None,
        mtime_epoch: Optional[float] = None,
    ) -> Optional[FileResult]:
        """Phase 2 — scan file content.

        If *prior* is provided (from :meth:`check_file`), the file-rule
        evaluation is skipped and the targeted content rules are used.
        If *prior* is ``None``, standalone mode: calls check_file first,
        then scan_with_data.
        """
        if prior is None:
            if file_path is None or size is None or mtime_epoch is None:
                raise ValueError(
                    "file_path, size, and mtime_epoch are required "
                    "when prior is not provided"
                )
            prior = self._scanner.check_file(file_path, size, mtime_epoch)
            if prior.status == FileCheckStatus.DISCARD:
                return None
            if prior.status == FileCheckStatus.SNAFFLE:
                if prior.result and prior.result.triage == Triage.BLACK:
                    return self._apply_filters(prior.result)
                # Fall through to content scan — caller explicitly provided data
                prior._can_scan_content = True

        if prior.status == FileCheckStatus.DISCARD:
            return None
        if prior.status == FileCheckStatus.SNAFFLE:
            if prior.result and prior.result.triage == Triage.BLACK:
                return self._apply_filters(prior.result)
            # Fall through to content scan — caller explicitly provided data
            prior._can_scan_content = True

        result = self._scanner.scan_with_data(data, prior)
        return self._apply_filters(result)

    # ------------------------------------------------------------------ certs

    def check_certificate(
        self,
        file_path: str,
        size: int,
        mtime_epoch: float,
        data: bytes,
    ) -> Optional[FileResult]:
        """Check certificate data for private keys.

        Returns a RED :class:`FileResult` if a private key is found,
        ``None`` otherwise.

        Note: this is a low-level method that bypasses file-rule evaluation
        (e.g. DISCARD rules). Use :meth:`walk` or :meth:`check_file` +
        :meth:`scan_content` for the full classification pipeline.
        """
        ctx = FileContext.from_path(file_path, size, mtime_epoch)
        result = self._scanner._evaluate_certificate(ctx, data)
        return self._apply_filters(result)

    # ------------------------------------------------------------------ archives

    def peek_archive(
        self,
        file_path: str,
        size: int,
        mtime_epoch: float,
        data: bytes,
    ) -> Optional[FileResult]:
        """List filenames inside an archive and evaluate file rules.

        Supports ZIP, 7z, and RAR formats.

        Note: this is a low-level method that bypasses file-rule evaluation
        on the archive file itself (e.g. DISCARD rules). Use :meth:`walk`
        or :meth:`check_file` + :meth:`scan_content` for the full
        classification pipeline.
        """
        ctx = FileContext.from_path(file_path, size, mtime_epoch)
        result = self._scanner._evaluate_archive(ctx, data)
        return self._apply_filters(result)

    # ------------------------------------------------------------------ internal

    def _apply_filters(self, result: Optional[FileResult]) -> Optional[FileResult]:
        """Apply min_interest and match_filter to a result."""
        if not result:
            return None
        if result.triage.below(self._min_interest):
            return None
        if self._match_re:
            if not self._match_re.search(result.match_haystack()):
                return None
        return result


# Backwards compatibility alias
SnafflerEngine = Snaffler
