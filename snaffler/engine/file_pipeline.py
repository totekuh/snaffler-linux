import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
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
        self.walk_timeout = cfg.advanced.walk_timeout or None  # 0 → no timeout

        self.tree_walker = TreeWalker(cfg,
                                      state=state)

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
        file_queue = queue.Queue(maxsize=10_000)

        walked_shares: list = []
        results_count = 0
        skipped_files = 0
        producer_error = []  # captures KeyboardInterrupt from producer

        # ---------- Producer: tree walking → queue ----------
        def _producer():
            # on_file runs in executor worker threads; use mutable container
            # instead of nonlocal (GIL-atomic += 1 on list element is safe)
            skip_count = [0]

            def on_file(unc_path, size, mtime):
                """Callback invoked by TreeWalker for each file discovered."""
                if self.state and self.state.should_skip_file(unc_path):
                    skip_count[0] += 1
                    if self.progress:
                        self.progress.files_total += 1
                        self.progress.files_scanned += 1
                    return
                if self.progress:
                    self.progress.files_total += 1
                file_queue.put((unc_path, size, mtime))

            try:
                with ThreadPoolExecutor(max_workers=self.tree_threads) as executor:
                    cancel_events = {}
                    future_to_path = {}
                    for path in paths:
                        cancel = threading.Event()
                        cancel_events[path] = cancel
                        future = executor.submit(
                            self.tree_walker.walk_tree, path, on_file, cancel
                        )
                        future_to_path[future] = path

                    try:
                        for future in as_completed(future_to_path):
                            path = future_to_path[future]
                            try:
                                future.result(timeout=self.walk_timeout)
                            except TimeoutError:
                                cancel_events[path].set()
                                logger.warning(
                                    f"Timeout walking {path} after {self.walk_timeout}s, cancelling"
                                )
                                if self.progress:
                                    self.progress.shares_walked += 1
                                continue
                            except Exception as e:
                                logger.debug(f"Error walking {path}: {e}")
                                if self.progress:
                                    self.progress.shares_walked += 1
                                continue

                            walked_shares.append(path)
                            if self.progress:
                                self.progress.shares_walked += 1
                    except KeyboardInterrupt:
                        for ev in cancel_events.values():
                            ev.set()
                        executor.shutdown(wait=False, cancel_futures=True)
                        producer_error.append(KeyboardInterrupt())
            finally:
                nonlocal skipped_files
                skipped_files = skip_count[0]
                # Push sentinels so consumers exit
                for _ in range(self.file_threads):
                    file_queue.put(_SENTINEL)

        # ---------- Consumer: queue → scan ----------
        consumer_results = [0]  # mutable container for thread access
        consumer_lock = threading.Lock()

        def _consumer():
            while True:
                try:
                    item = file_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                if item is _SENTINEL:
                    return

                unc_path, size, mtime = item

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
