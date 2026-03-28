import fnmatch
import logging
import queue
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import List

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.file_scanner import FileScanner
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.classifiers.rules import Triage
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.shares import share_matches_filter
from snaffler.discovery.smb_tree_walker import SMBTreeWalker
from snaffler.discovery.tree import TreeWalker
from snaffler.resume.scan_state import ScanState
from snaffler.utils.fatal import check_fatal_os_error
from snaffler.utils.logger import log_file_result
from snaffler.utils.progress import ProgressState

logger = logging.getLogger("snaffler")

_SENTINEL = None  # poison pill to signal consumer threads to exit

_BATCH_SIZE = 500
_BATCH_INTERVAL = 1.0  # seconds
_MAX_ENQUEUED = 500_000  # clear enqueued set to bound memory usage


def _extract_share_unc(unc_path: str) -> str:
    """Extract //server/share from a full UNC path.

    Delegates to :func:`snaffler.utils.path_utils.extract_share_root`.
    """
    from snaffler.utils.path_utils import extract_share_root
    return extract_share_root(unc_path)


class _BatchWriter:
    """Daemon thread that batches dir/file inserts and file-checked marks into SQLite."""

    def __init__(self, state: ScanState):
        self._state = state
        self._queue = queue.Queue()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(
            target=self._run, name="batch-writer", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout=30):
        self._queue.put(None)  # sentinel
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning(f"Batch writer did not finish within {timeout}s")

    def put_dir(self, unc_path: str, share: str):
        self._queue.put(("dir", unc_path, share))

    def put_file(self, unc_path: str, share: str, size: int, mtime: float):
        self._queue.put(("file", unc_path, share, size, mtime))

    def enqueue_checked(self, unc_path: str):
        """Queue a file-checked mark for batched DB write."""
        self._queue.put(("checked", unc_path))

    def _run(self):
        dir_buf = []
        file_buf = []
        checked_buf = []
        deadline = time.monotonic() + _BATCH_INTERVAL

        while True:
            try:
                timeout = max(0, deadline - time.monotonic())
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                item = "flush"

            if item is None:
                # Sentinel — drain remaining items and flush
                while True:
                    try:
                        remaining = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if remaining is None:
                        continue
                    kind = remaining[0]
                    if kind == "dir":
                        dir_buf.append((remaining[1], remaining[2]))
                    elif kind == "file":
                        file_buf.append((remaining[1], remaining[2], remaining[3], remaining[4]))
                    elif kind == "checked":
                        checked_buf.append(remaining[1])
                self._flush(dir_buf, file_buf, checked_buf)
                return

            if item == "flush":
                self._flush(dir_buf, file_buf, checked_buf)
                dir_buf.clear()
                file_buf.clear()
                checked_buf.clear()
                deadline = time.monotonic() + _BATCH_INTERVAL
                continue

            kind = item[0]
            if kind == "dir":
                dir_buf.append((item[1], item[2]))
            elif kind == "file":
                file_buf.append((item[1], item[2], item[3], item[4]))
            elif kind == "checked":
                checked_buf.append(item[1])

            if len(dir_buf) + len(file_buf) + len(checked_buf) >= _BATCH_SIZE:
                self._flush(dir_buf, file_buf, checked_buf)
                dir_buf.clear()
                file_buf.clear()
                checked_buf.clear()
                deadline = time.monotonic() + _BATCH_INTERVAL

    def _flush(self, dir_buf, file_buf, checked_buf=None):
        try:
            if dir_buf:
                self._state.store_dirs(dir_buf)
            if file_buf:
                self._state.store_files(file_buf)
            if checked_buf:
                self._state.store.mark_files_checked_batch(checked_buf)
        except Exception as e:
            logger.warning(
                f"Batch writer flush error ({len(dir_buf)} dirs, "
                f"{len(file_buf)} files, "
                f"{len(checked_buf) if checked_buf else 0} checked): {e}"
            )


class FilePipeline:
    def __init__(
            self,
            cfg: SnafflerConfiguration,
            state: ScanState | None = None,
            progress: ProgressState | None = None,
            tree_walker: TreeWalker | None = None,
            file_accessor: FileAccessor | None = None,
    ):
        self.cfg = cfg
        self.state = state
        self.progress = progress

        self.tree_threads = cfg.advanced.tree_threads
        self.file_threads = cfg.advanced.file_threads
        self.max_per_share = cfg.advanced.max_tree_threads_per_share  # 0 = unlimited

        self.tree_walker = tree_walker or SMBTreeWalker(cfg)

        file_accessor = file_accessor or SMBFileAccessor(cfg)
        rule_evaluator = RuleEvaluator(
            file_rules=cfg.rules.file,
            content_rules=cfg.rules.content,
            postmatch_rules=cfg.rules.postmatch,
        )
        self.file_scanner = FileScanner(
            cfg=cfg,
            file_accessor=file_accessor,
            rule_evaluator=rule_evaluator,
        )

    def run(self, paths: List[str]) -> int:
        logger.info(f"Starting file discovery on {len(paths)} paths")

        # ---------- Resume: skip fully-processed shares ----------
        skipped_shares = 0
        if self.state:
            before = len(paths)
            paths = [p for p in paths if not self.state.should_skip_share(p)]
            skipped_shares = before - len(paths)
            if skipped_shares:
                logger.info(f"Resume: skipped {skipped_shares} fully-processed shares")

        if self.progress:
            self.progress.shares_total = len(paths) + skipped_shares
            self.progress.shares_walked = skipped_shares

        if not paths:
            logger.info("No shares to walk")
            return 0

        # Bounded queue: lightweight (path, size, mtime) tuples, ~240 bytes each
        file_queue = queue.Queue(maxsize=100_000)

        walked_shares: list = []
        results_count = 0
        producer_error = []  # captures KeyboardInterrupt from producer

        # Shared batch writer — used by producer (dir/file inserts) and
        # consumers (file-checked marks).  Created at run() scope so both
        # closures can reference it; started before threads, stopped after
        # all consumers finish.
        batch_writer = None
        if self.state:
            batch_writer = _BatchWriter(self.state)
            batch_writer.start()

        # ---------- Producer: parallel tree walking → queue ----------
        def _producer():
            shutdown = threading.Event()
            enqueued = set()
            enqueued_lock = threading.Lock()

            def on_file(unc_path, size, mtime):
                """Callback invoked by TreeWalker for each file discovered."""
                normalized = unc_path.lower()
                with enqueued_lock:
                    if normalized in enqueued:
                        return
                    enqueued.add(normalized)
                    if len(enqueued) > _MAX_ENQUEUED:
                        enqueued.clear()
                if self.state and self.state.should_skip_file(unc_path):
                    if self.progress:
                        self.progress.files_total += 1
                        self.progress.files_scanned += 1
                    return
                if self.progress:
                    self.progress.files_total += 1
                if batch_writer:
                    share_unc = _extract_share_unc(unc_path)
                    batch_writer.put_file(unc_path, share_unc, size, mtime)
                while not shutdown.is_set():
                    try:
                        file_queue.put((unc_path, size, mtime), timeout=1.0)
                        return
                    except queue.Full:
                        continue

            def on_dir(unc_path):
                """Callback invoked by TreeWalker for each subdirectory discovered."""
                if batch_writer:
                    share_unc = _extract_share_unc(unc_path)
                    batch_writer.put_dir(unc_path, share_unc)

            try:
                with ThreadPoolExecutor(max_workers=self.tree_threads) as executor:
                    # Maps: future → dir UNC, future → share root UNC
                    dir_for_future = {}
                    share_for_future = {}
                    # Per-share pending futures count (active in executor)
                    share_pending = {}
                    # Shares that had at least one walk error (don't mark done)
                    shares_with_errors = set()
                    # Cancel events per share root
                    cancel_events = {}
                    pending = set()
                    # Track all submitted dirs to prevent double walks
                    submitted_dirs = set()

                    # --- Fair-share scheduling ---
                    max_per_share = self.max_per_share  # 0 = unlimited
                    share_buffer = {}   # share_key -> deque of subdir paths
                    share_root_map = {} # share_key -> original share_root string

                    def _submit_dir(subdir, share_root, cancel_ev):
                        """Submit a directory walk, or buffer if share is at its thread limit."""
                        key = share_root.lower()
                        if max_per_share and share_pending.get(key, 0) >= max_per_share:
                            if key not in share_buffer:
                                share_buffer[key] = deque()
                            share_buffer[key].append(subdir)
                            return
                        fut = executor.submit(
                            self.tree_walker.walk_directory,
                            subdir, on_file, on_dir, cancel_ev,
                        )
                        dir_for_future[fut] = subdir
                        share_for_future[fut] = share_root
                        share_pending[key] = share_pending.get(key, 0) + 1
                        pending.add(fut)

                    def _drain_buffer(key):
                        """Submit buffered dirs for a share until at its thread limit."""
                        if key not in share_buffer:
                            return
                        buf = share_buffer[key]
                        cancel_ev = cancel_events.get(key, threading.Event())
                        root = share_root_map.get(key)
                        while buf and (not max_per_share or share_pending.get(key, 0) < max_per_share):
                            subdir = buf.popleft()
                            # No submitted_dirs check needed — dirs are dedup'd
                            # before entering the buffer.
                            fut = executor.submit(
                                self.tree_walker.walk_directory,
                                subdir, on_file, on_dir, cancel_ev,
                            )
                            dir_for_future[fut] = subdir
                            share_for_future[fut] = root
                            share_pending[key] = share_pending.get(key, 0) + 1
                            pending.add(fut)
                        if not buf:
                            del share_buffer[key]

                    # Pre-populate with already-walked dirs from resume DB
                    if self.state:
                        for d in self.state.load_walked_dirs():
                            submitted_dirs.add(d.lower())

                    # --- Seed initial share roots ---
                    for path in paths:
                        # Check seed paths against --exclude-unc patterns
                        exclude_patterns = getattr(self.tree_walker, '_exclude_unc', None) or self.cfg.targets.exclude_unc
                        if exclude_patterns:
                            path_lower = path.lower()
                            if any(fnmatch.fnmatch(path_lower, p.lower()) for p in exclude_patterns):
                                logger.debug(f"Skipped share root {path} due to --exclude-unc filter")
                                if self.progress:
                                    self.progress.shares_walked += 1
                                continue
                        key = path.lower()
                        # Resume: skip shares already fully processed
                        if self.state and self.state.should_skip_share(path):
                            logger.debug(f"Resume: skipping done share {path}")
                            if self.progress:
                                self.progress.shares_walked += 1
                            submitted_dirs.add(key)
                            continue
                        cancel = threading.Event()
                        cancel_events[key] = cancel
                        share_root_map[key] = path
                        # Resume: share root already walked — skip re-listing,
                        # only unwalked subdirectories will be resumed below.
                        if key in submitted_dirs:
                            logger.debug(f"Resume: share root already walked {path}")
                            share_pending[key] = 0
                            continue
                        submitted_dirs.add(key)
                        future = executor.submit(
                            self.tree_walker.walk_directory,
                            path, on_file, on_dir, cancel,
                        )
                        dir_for_future[future] = path
                        share_for_future[future] = path
                        share_pending[key] = 1
                        pending.add(future)

                    # --- Resume: re-walk unwalked directories ---
                    if self.state:
                        max_depth = self.cfg.scanning.max_depth
                        for unwalked_dir in self.state.load_unwalked_dirs():
                            dir_lower = unwalked_dir.lower()
                            # Find which share this dir belongs to by UNC
                            # extraction first, then fall back to prefix
                            # matching (needed for local paths where
                            # _extract_share_unc doesn't match the raw root).
                            share_root_unc = _extract_share_unc(unwalked_dir)
                            key = share_root_unc.lower()
                            if key not in cancel_events:
                                # Prefix match: find the share root this dir
                                # is a child of (handles local FS paths).
                                key = None
                                for ck in cancel_events:
                                    if dir_lower == ck or dir_lower.startswith(ck.rstrip("/") + "/"):
                                        key = ck
                                        break
                                if key is None:
                                    continue
                            share_root = share_root_map.get(key, share_root_unc)
                            # Skip dirs already submitted (e.g. share roots)
                            if dir_lower in submitted_dirs:
                                continue
                            # Respect --max-depth on resume
                            if max_depth is not None and share_root:
                                rel = dir_lower[len(key):].strip("/")
                                depth = len(rel.split("/")) if rel else 0
                                if depth > max_depth:
                                    continue
                            submitted_dirs.add(dir_lower)
                            _submit_dir(unwalked_dir, share_root, cancel_events[key])

                    # --- Resume: finalize shares with no remaining work ---
                    # Shares whose root was already walked and have no
                    # unwalked subdirs are effectively done — mark them now
                    # since the fan-out loop won't see any futures for them.
                    for key in list(share_root_map):
                        if share_pending.get(key, 0) == 0 and key not in share_buffer:
                            root = share_root_map[key]
                            if self.progress:
                                self.progress.shares_walked += 1
                            if key not in shares_with_errors:
                                walked_shares.append(root)

                    # --- Resume: seed unchecked files into queue ---
                    # Seed all unchecked files from the DB. Files from dirs
                    # being re-walked may also be re-discovered via on_file,
                    # but the enqueued set + should_skip_file dedup handles that.
                    if self.state:
                        include_filter = self.cfg.targets.share_filter
                        exclude_filter = self.cfg.targets.exclude_share
                        exclude_dir_patterns = self.cfg.targets.exclude_unc
                        for unc_path, size, mtime in self.state.iter_unchecked_files():
                            file_share = _extract_share_unc(unc_path).lower()
                            # Respect --share / --exclude-share for DB-seeded files
                            share_name = file_share.rstrip("/").rsplit("/", 1)[-1]
                            if not share_matches_filter(share_name, include_filter, exclude_filter):
                                continue
                            # Respect --exclude-unc for DB-seeded files
                            if exclude_dir_patterns:
                                path_lower = unc_path.lower()
                                if any(fnmatch.fnmatch(path_lower, p.lower()) for p in exclude_dir_patterns):
                                    continue
                            normalized = unc_path.lower()
                            with enqueued_lock:
                                if normalized in enqueued:
                                    continue
                                enqueued.add(normalized)
                            if self.state.should_skip_file(unc_path):
                                continue
                            if self.progress:
                                self.progress.files_total += 1
                            while not shutdown.is_set():
                                try:
                                    file_queue.put((unc_path, size or 0, mtime or 0.0), timeout=1.0)
                                    break
                                except queue.Full:
                                    continue

                    # --- Fan-out loop ---
                    try:
                        while pending:
                            done, pending = wait(
                                pending, return_when=FIRST_COMPLETED,
                            )
                            for future in done:
                                dir_unc = dir_for_future.pop(future, None)
                                share_root = share_for_future.pop(future, None)

                                walk_ok = False
                                try:
                                    # Socket timeout (smb_timeout, default 5s) bounds
                                    # each recv() inside listPath; no future timeout needed.
                                    subdirs = future.result()
                                    walk_ok = True
                                except Exception as e:
                                    check_fatal_os_error(e)
                                    logger.debug(f"Error walking {dir_unc}: {e}")
                                    subdirs = []
                                    if share_root:
                                        shares_with_errors.add(share_root.lower())

                                # Only mark walked on success — failed dirs retry on resume
                                if self.state and dir_unc and walk_ok:
                                    self.state.mark_dir_walked(dir_unc)

                                # Submit subdirectories (or buffer if share at thread limit)
                                max_depth = self.cfg.scanning.max_depth
                                for subdir in subdirs:
                                    if subdir.lower() in submitted_dirs:
                                        continue
                                    if max_depth is not None and share_root:
                                        rel = subdir.lower()[len(share_root.lower()):].strip("/")
                                        depth = len(rel.split("/")) if rel else 0
                                        if depth > max_depth:
                                            # Store in DB so a future resume with
                                            # higher --max-depth can pick it up
                                            if self.state:
                                                self.state.store_dir(subdir, share_root)
                                            continue
                                    submitted_dirs.add(subdir.lower())
                                    cancel_ev = cancel_events.get(share_root.lower(), threading.Event())
                                    _submit_dir(subdir, share_root, cancel_ev)

                                # Decrement active count and drain buffer
                                if share_root:
                                    key = share_root.lower()
                                    share_pending[key] -= 1
                                    _drain_buffer(key)
                                    # Track share completion — pending == 0 AND buffer empty
                                    if share_pending.get(key, 0) == 0 and key not in share_buffer:
                                        # Always count as walked for progress display
                                        if self.progress:
                                            self.progress.shares_walked += 1
                                        # Only mark done in resume DB if no errors
                                        # (shares with errors retry failed dirs on resume)
                                        if key not in shares_with_errors:
                                            walked_shares.append(share_root)
                                        else:
                                            logger.warning(
                                                f"Share {share_root} completed with walk errors "
                                                f"(will retry failed dirs on resume)"
                                            )

                    except KeyboardInterrupt:
                        shutdown.set()
                        for ev in cancel_events.values():
                            ev.set()
                        executor.shutdown(wait=False, cancel_futures=True)
                        producer_error.append(KeyboardInterrupt())
            finally:
                # Push sentinels so consumers exit — drain queue first if
                # full, then push with timeout to guarantee delivery.
                for _ in range(self.file_threads):
                    while True:
                        try:
                            file_queue.put(_SENTINEL, timeout=5)
                            break
                        except queue.Full:
                            # Drain one item and retry
                            try:
                                file_queue.get_nowait()
                            except queue.Empty:
                                pass

        # ---------- Consumer: queue → scan ----------
        consumer_results = [0]  # mutable container for thread access
        consumer_lock = threading.Lock()

        def _consumer():
            while True:
                try:
                    item = file_queue.get(timeout=0.1)
                except queue.Empty:
                    continue

                if item is _SENTINEL:
                    return

                unc_path, size, mtime = item

                if self.state and self.state.should_skip_file(unc_path):
                    if self.progress:
                        self.progress.files_scanned += 1
                    continue

                if self.progress:
                    self.progress.files_in_progress += 1
                try:
                    result = self.file_scanner.scan_file(unc_path, size, mtime)

                    # Mark done only on success — transport errors skip this
                    # so the file is retried on resume.
                    if self.state:
                        self.state.mark_file_done(unc_path)  # in-memory dedup
                        if batch_writer:
                            batch_writer.enqueue_checked(unc_path)  # DB write batched

                    if result:
                        # Log the finding
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
                        # Download if configured
                        if (
                                self.cfg.scanning.snaffle
                                and result.size <= self.cfg.scanning.max_file_bytes
                                and self.file_scanner.file_accessor is not None
                        ):
                            self.file_scanner.file_accessor.copy_to_local(
                                unc_path,
                                self.cfg.scanning.snaffle_path,
                            )

                        with consumer_lock:
                            consumer_results[0] += 1
                        if self.progress:
                            self.progress.files_matched += 1
                            self._count_severity(result)

                except Exception as e:
                    check_fatal_os_error(e)
                    # Transport error — file NOT marked done, will retry on resume
                    logger.warning(f"Error scanning {unc_path}: {e}")
                finally:
                    if self.progress:
                        self.progress.files_scanned += 1
                        self.progress.files_in_progress -= 1

        # ---------- Launch producer + consumers ----------
        producer_thread = threading.Thread(target=_producer, name="walk-producer", daemon=True)
        consumer_threads = [
            threading.Thread(target=_consumer, name=f"scan-consumer-{i}", daemon=True)
            for i in range(self.file_threads)
        ]

        producer_thread.start()
        for t in consumer_threads:
            t.start()

        interrupted = False
        try:
            producer_thread.join()
            for t in consumer_threads:
                t.join()
        except KeyboardInterrupt:
            interrupted = True
            # Drain queue and push sentinels so consumers can exit
            while True:
                try:
                    file_queue.get_nowait()
                except queue.Empty:
                    break
            for _ in range(self.file_threads):
                try:
                    file_queue.put_nowait(_SENTINEL)
                except queue.Full:
                    pass
            for t in consumer_threads:
                t.join(timeout=5)
        finally:
            # Stop batch writer after all consumers finish so queued
            # file-checked marks are flushed to the DB.
            if batch_writer:
                timeout = 5 if (interrupted or producer_error) else 30
                batch_writer.stop(timeout=timeout)

        if interrupted:
            raise KeyboardInterrupt()

        # Re-raise KeyboardInterrupt from producer thread
        if producer_error:
            raise producer_error[0]

        results_count = consumer_results[0]

        # Mark shares as fully processed only after all files are scanned.
        self._mark_shares_done(walked_shares)

        if results_count:
            logger.info(f"Scan completed: {results_count} files matched")
        elif self.progress and self.progress.files_total == 0:
            logger.warning("No files found")
        else:
            logger.info("Scan completed: no matches")

        return results_count

    def _mark_shares_done(self, walked_shares: list):
        """Mark successfully walked shares as fully processed in state DB."""
        if self.state:
            for share_path in walked_shares:
                self.state.mark_share_done(share_path)

    def close(self):
        """Close all cached connections held by the tree walker and file accessor."""
        try:
            self.tree_walker.close()
        except Exception:
            pass
        try:
            self.file_scanner.file_accessor.close()
        except Exception:
            pass

    def _count_severity(self, result):
        """Increment the per-severity counter on progress state."""
        triage = result.triage
        if triage == Triage.BLACK:
            self.progress.severity_black += 1
        elif triage == Triage.RED:
            self.progress.severity_red += 1
        elif triage == Triage.YELLOW:
            self.progress.severity_yellow += 1
        elif triage == Triage.GREEN:
            self.progress.severity_green += 1
