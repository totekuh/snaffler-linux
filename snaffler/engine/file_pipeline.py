import logging
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import List

from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.file_scanner import FileScanner
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.tree import TreeWalker
from snaffler.resume.scan_state import ScanState
from snaffler.utils.progress import ProgressState

logger = logging.getLogger("snaffler")

_SENTINEL = None  # poison pill to signal consumer threads to exit

_BATCH_SIZE = 500
_BATCH_INTERVAL = 1.0  # seconds


def _extract_share_unc(unc_path: str) -> str:
    """Extract //server/share from a full UNC path."""
    parts = unc_path.replace("\\", "/").split("/")
    parts = [p for p in parts if p]
    if len(parts) >= 2:
        return f"//{parts[0]}/{parts[1]}"
    return unc_path


class _BatchWriter:
    """Daemon thread that batches dir/file inserts into SQLite."""

    def __init__(self, state: ScanState):
        self._state = state
        self._queue = queue.Queue()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(
            target=self._run, name="batch-writer", daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._queue.put(None)  # sentinel
        if self._thread is not None:
            self._thread.join(timeout=30)
            if self._thread.is_alive():
                logger.warning("Batch writer did not finish within 30s")

    def put_dir(self, unc_path: str, share: str):
        self._queue.put(("dir", unc_path, share))

    def put_file(self, unc_path: str, share: str, size: int, mtime: float):
        self._queue.put(("file", unc_path, share, size, mtime))

    def _run(self):
        dir_buf = []
        file_buf = []
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
                self._flush(dir_buf, file_buf)
                return

            if item == "flush":
                self._flush(dir_buf, file_buf)
                dir_buf.clear()
                file_buf.clear()
                deadline = time.monotonic() + _BATCH_INTERVAL
                continue

            kind = item[0]
            if kind == "dir":
                dir_buf.append((item[1], item[2]))
            elif kind == "file":
                file_buf.append((item[1], item[2], item[3], item[4]))

            if len(dir_buf) + len(file_buf) >= _BATCH_SIZE:
                self._flush(dir_buf, file_buf)
                dir_buf.clear()
                file_buf.clear()
                deadline = time.monotonic() + _BATCH_INTERVAL

    def _flush(self, dir_buf, file_buf):
        try:
            if dir_buf:
                self._state.store_dirs(dir_buf)
            if file_buf:
                self._state.store_files(file_buf)
        except Exception as e:
            logger.debug(f"Batch writer flush error: {e}")


class FilePipeline:
    def __init__(
            self,
            cfg: SnafflerConfiguration,
            state: ScanState | None = None,
            progress: ProgressState | None = None,
    ):
        self.cfg = cfg
        self.state = state
        self.progress = progress

        self.tree_threads = cfg.advanced.tree_threads
        self.file_threads = cfg.advanced.file_threads

        self.tree_walker = TreeWalker(cfg)

        file_accessor = SMBFileAccessor(cfg)
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

        # ---------- Producer: parallel tree walking → queue ----------
        def _producer():
            batch_writer = None
            shutdown = threading.Event()

            if self.state:
                batch_writer = _BatchWriter(self.state)
                batch_writer.start()

            def on_file(unc_path, size, mtime):
                """Callback invoked by TreeWalker for each file discovered."""
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
                    # Per-share pending futures count
                    share_pending = {}
                    # Shares that had at least one walk error (don't mark done)
                    shares_with_errors = set()
                    # Cancel events per share root
                    cancel_events = {}
                    pending = set()
                    # Track all submitted dirs to prevent double walks
                    submitted_dirs = set()

                    # --- Seed initial share roots ---
                    for path in paths:
                        cancel = threading.Event()
                        cancel_events[path] = cancel
                        submitted_dirs.add(path.lower())
                        future = executor.submit(
                            self.tree_walker.walk_directory,
                            path, on_file, on_dir, cancel,
                        )
                        dir_for_future[future] = path
                        share_for_future[future] = path
                        share_pending[path] = 1
                        pending.add(future)

                    # --- Resume: re-walk unwalked directories ---
                    if self.state:
                        for unwalked_dir in self.state.load_unwalked_dirs():
                            share_root = _extract_share_unc(unwalked_dir)
                            # Only re-walk dirs belonging to shares we're processing
                            if share_root not in cancel_events:
                                continue
                            # Skip dirs already submitted (e.g. share roots)
                            if unwalked_dir.lower() in submitted_dirs:
                                continue
                            submitted_dirs.add(unwalked_dir.lower())
                            cancel = cancel_events[share_root]
                            future = executor.submit(
                                self.tree_walker.walk_directory,
                                unwalked_dir, on_file, on_dir, cancel,
                            )
                            dir_for_future[future] = unwalked_dir
                            share_for_future[future] = share_root
                            share_pending[share_root] = share_pending.get(share_root, 0) + 1
                            pending.add(future)

                    # --- Resume: seed unchecked files into queue ---
                    # Only seed files from shares NOT being actively walked
                    # (active shares will re-discover their files via walk_directory)
                    if self.state:
                        walked_roots = {p.lower() for p in paths}
                        unchecked = self.state.load_unchecked_files()
                        for unc_path, size, mtime in unchecked:
                            file_share = _extract_share_unc(unc_path).lower()
                            if file_share in walked_roots:
                                continue  # will be re-discovered by live walk
                            if self.state.should_skip_file(unc_path):
                                continue
                            if self.progress:
                                self.progress.files_total += 1
                            file_queue.put((unc_path, size or 0, mtime or 0.0))

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
                                    logger.debug(f"Error walking {dir_unc}: {e}")
                                    subdirs = []
                                    if share_root:
                                        shares_with_errors.add(share_root)

                                # Only mark walked on success — failed dirs retry on resume
                                if self.state and dir_unc and walk_ok:
                                    self.state.mark_dir_walked(dir_unc)

                                # Submit subdirectories
                                for subdir in subdirs:
                                    if subdir.lower() in submitted_dirs:
                                        continue
                                    submitted_dirs.add(subdir.lower())
                                    cancel = cancel_events.get(share_root, threading.Event())
                                    sub_future = executor.submit(
                                        self.tree_walker.walk_directory,
                                        subdir, on_file, on_dir, cancel,
                                    )
                                    dir_for_future[sub_future] = subdir
                                    share_for_future[sub_future] = share_root
                                    share_pending[share_root] = share_pending.get(share_root, 0) + 1
                                    pending.add(sub_future)

                                # Track share completion
                                if share_root:
                                    share_pending[share_root] -= 1
                                    if share_pending[share_root] == 0:
                                        # Don't mark shares with errors as done — retry on resume
                                        if share_root not in shares_with_errors:
                                            walked_shares.append(share_root)
                                            if self.progress:
                                                self.progress.shares_walked += 1

                    except KeyboardInterrupt:
                        shutdown.set()
                        for ev in cancel_events.values():
                            ev.set()
                        executor.shutdown(wait=False, cancel_futures=True)
                        producer_error.append(KeyboardInterrupt())
            finally:
                if batch_writer:
                    batch_writer.stop()
                # Push sentinels so consumers exit
                for _ in range(self.file_threads):
                    file_queue.put(_SENTINEL)

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

                if self.progress:
                    self.progress.files_in_progress += 1
                try:
                    result = self.file_scanner.scan_file(unc_path, size, mtime)

                    if self.state:
                        self.state.mark_file_done(unc_path)

                    if self.progress:
                        self.progress.files_scanned += 1

                    if result:
                        with consumer_lock:
                            consumer_results[0] += 1
                        if self.progress:
                            self.progress.files_matched += 1
                            self._count_severity(result)

                except Exception as e:
                    logger.debug(f"Error scanning {unc_path}: {e}")
                finally:
                    if self.progress:
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

        try:
            producer_thread.join()
            for t in consumer_threads:
                t.join()
        except KeyboardInterrupt:
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
            raise

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

    def _count_severity(self, result):
        """Increment the per-severity counter on progress state."""
        from snaffler.classifiers.rules import Triage

        triage = result.triage
        if triage == Triage.BLACK:
            self.progress.severity_black += 1
        elif triage == Triage.RED:
            self.progress.severity_red += 1
        elif triage == Triage.YELLOW:
            self.progress.severity_yellow += 1
        elif triage == Triage.GREEN:
            self.progress.severity_green += 1
