"""
Logging utilities for Snaffler Linux
"""

import hashlib
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class FindingsOnlyFilter(logging.Filter):
    def filter(self, record):
        return bool(getattr(record, "is_data", False))


class Colors:
    BLACK = '\033[90m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    GRAY = '\033[37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def _logger_has_file_handler(logger: logging.Logger) -> bool:
    return any(isinstance(h, logging.FileHandler) for h in logger.handlers)


class SnafflerFormatter(logging.Formatter):
    LEVEL_COLORS = {
        'DEBUG': Colors.GRAY,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.RED + Colors.BOLD,
    }

    def __init__(self, logger: logging.Logger):
        super().__init__()
        self.logger = logger

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created).strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        level = record.levelname
        message = record.getMessage()

        use_colors = (
                sys.stdout.isatty()
                and not _logger_has_file_handler(self.logger)
        )

        if use_colors:
            color = self.LEVEL_COLORS.get(level, '')
            return (
                f"{Colors.GRAY}[{timestamp}]{Colors.RESET} "
                f"{color}[{level}]{Colors.RESET} {message}"
            )
        return f"[{timestamp}] [{level}] {message}"


class SnafflerJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }

        for field in (
                "file_path",
                "triage",
                "rule_name",
                "match_context",
                "size",
                "mtime",
                "finding_id",
        ):
            if hasattr(record, field):
                data[field] = getattr(record, field)

        return json.dumps(data)

class SnafflerTSVFormatter(logging.Formatter):
    FIELDS = (
        "timestamp",
        "triage",
        "rule_name",
        "file_path",
        "size",
        "mtime",
        "finding_id",
        "match_context",
    )

    def format(self, record: logging.LogRecord) -> str:
        values = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
        }

        row = []
        for field in self.FIELDS:
            val = values.get(field, getattr(record, field, ""))
            if val is None:
                val = ""

            # normalize FIRST
            val = str(val).replace("\r\n", "\n").replace("\n\r", "\n")

            # then escape
            val = val.replace("\t", " ").replace("\n", "\\n")

            row.append(val)

        return "\t".join(row)



def setup_logging(
        log_level: str = "info",
        log_to_file: bool = False,
        log_file_path: Optional[str] = None,
        log_to_console: bool = True,
        log_type: str = "plain",
) -> logging.Logger:

    level_map = {
        "trace": logging.DEBUG,
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "data": logging.WARNING,
    }

    level = level_map.get(log_level.lower(), logging.INFO)

    logger = logging.getLogger("snaffler")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    if log_to_console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        ch.setFormatter(SnafflerFormatter(logger))
        logger.addHandler(ch)

    if log_to_file and log_file_path:
        Path(log_file_path).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file_path, mode="a", encoding="utf-8", errors="replace")

        if log_level == "data":
            fh.setLevel(logging.DEBUG)
            fh.addFilter(FindingsOnlyFilter())
        else:
            fh.setLevel(level)

        if log_type == "json":
            fh.setFormatter(SnafflerJSONFormatter())
        elif log_type == "tsv":
            Path(log_file_path).parent.mkdir(parents=True, exist_ok=True)
            with open(log_file_path, "w", encoding="utf-8") as f:
                f.write(
                    "timestamp\ttriage\trule_name\tfile_path\tsize\tmtime\tfinding_id\tmatch_context\n"
                )

            fh = logging.FileHandler(log_file_path, mode="a", encoding="utf-8", errors="replace")
            fh.setLevel(logging.DEBUG)
            fh.addFilter(FindingsOnlyFilter())
            fh.setFormatter(SnafflerTSVFormatter())
        else:
            fh.setFormatter(SnafflerFormatter(logger))

        logger.addHandler(fh)

    return logger


def _make_finding_id(file_path: str, rule_name: str) -> str:
    h = hashlib.sha1()
    h.update(f"{file_path}:{rule_name}".encode())
    return h.hexdigest()


def log_file_result(
        logger: logging.Logger,
        file_path: str,
        triage: str,
        rule_name: str,
        match: Optional[str] = None,
        context: Optional[str] = None,
        size: Optional[int] = None,
        modified: Optional[str] = None,
):

    use_colors = (
            sys.stdout.isatty()
            and not _logger_has_file_handler(logger)
    )

    triage_colors = {
        "Black": Colors.BLACK + Colors.BOLD,
        "Red": Colors.RED + Colors.BOLD,
        "Yellow": Colors.YELLOW + Colors.BOLD,
        "Green": Colors.GREEN,
        "Gray": Colors.GRAY,
    }

    color = triage_colors.get(triage, "") if use_colors else ""
    reset = Colors.RESET if use_colors else ""
    bold = Colors.BOLD if use_colors else ""

    parts = [f"{color}[{triage}]{reset}", f"[{rule_name}]"]

    if size is not None:
        parts.append(f"[{format_size(size)}]")
    if modified:
        parts.append(f"[mtime:{modified}]")

    parts.append(f"{bold}{file_path}{reset}")

    if match:
        parts.append(f"Match: {match}")
    if context:
        parts.append(f"Context: {context[:200]}...")

    is_json = any(
        isinstance(h.formatter, SnafflerJSONFormatter)
        for h in logger.handlers
    )

    message = "file_match" if is_json else " ".join(parts)

    extra = {
        "file_path": file_path,
        "triage": triage,
        "rule_name": rule_name,
        "finding_id": _make_finding_id(file_path, rule_name),
        "is_data": True,
    }

    if context:
        extra["match_context"] = context
    if size is not None:
        extra["size"] = size
    if modified:
        extra["mtime"] = modified

    logger.warning(message, extra=extra)


def print_completion_stats(start_time, progress=None):
    if not start_time:
        return

    logger = logging.getLogger("snaffler")
    end_time = datetime.now()
    duration = end_time - start_time

    seconds = int(duration.total_seconds())
    h, r = divmod(seconds, 3600)
    m, s = divmod(r, 60)

    logger.info("-" * 60)
    logger.info(f"Started:  {start_time:%Y-%m-%d %H:%M:%S}")
    logger.info(f"Finished: {end_time:%Y-%m-%d %H:%M:%S}")
    logger.info(
        f"Duration: {h}h {m}m {s}s" if h else
        f"Duration: {m}m {s}s" if m else
        f"Duration: {s}s"
    )
    if progress:
        parts = []
        if progress.computers_total:
            parts.append(f"Computers: {progress.computers_done}/{progress.computers_total}")
        if progress.shares_found:
            parts.append(f"Shares: {progress.shares_found}")
        if progress.files_total:
            parts.append(f"Files scanned: {progress.files_scanned}/{progress.files_total}")
        if progress.files_matched:
            parts.append(f"Matched: {progress.files_matched}")
        if parts:
            logger.info(" | ".join(parts))
    logger.info("-" * 60)


def format_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"
