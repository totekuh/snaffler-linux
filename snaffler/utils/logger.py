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


def _plain_file_handler(path: Path, level: int):
    h = FlushFileHandler(path, mode="a", encoding="utf-8", errors="replace")
    h.setLevel(level)
    h.setFormatter(SnafflerFileFormatter())
    return h



def _json_file_handler(path: Path):
    h = FlushFileHandler(path, mode="a", encoding="utf-8", errors="replace")
    h.setLevel(logging.DEBUG)
    h.addFilter(FindingsOnlyFilter())
    h.setFormatter(SnafflerJSONFormatter())
    return h


def _tsv_file_handler(path: Path):
    if not path.exists():
        path.write_text(
            "timestamp\ttriage\trule_name\tfile_path\tsize\tmtime\tfinding_id\tmatch_context\n",
            encoding="utf-8",
        )
    h = FlushFileHandler(path, mode="a", encoding="utf-8", errors="replace")
    h.setLevel(logging.DEBUG)
    h.addFilter(FindingsOnlyFilter())
    h.setFormatter(SnafflerTSVFormatter())
    return h


class FlushStreamHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        try:
            self.flush()
        except Exception:
            pass


class FlushFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        try:
            self.flush()
        except Exception:
            pass


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


class SnafflerConsoleFormatter(logging.Formatter):
    LEVEL_COLORS = {
        'DEBUG': Colors.GRAY,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.RED + Colors.BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created).strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        level = record.levelname
        message = record.getMessage()

        if sys.stdout.isatty():
            color = self.LEVEL_COLORS.get(level, '')
            return (
                f"{Colors.GRAY}[{timestamp}]{Colors.RESET} "
                f"{color}[{level}]{Colors.RESET} {message}"
            )

        return f"[{timestamp}] [{level}] {message}"


class SnafflerFileFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created).strftime(
            '%Y-%m-%d %H:%M:%S'
        )
        return f"[{timestamp}] [{record.levelname}] {record.getMessage()}"


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
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    level = level_map.get(log_level.lower(), logging.INFO)

    logger = logging.getLogger("snaffler")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    if log_to_console:
        ch = FlushStreamHandler(sys.stdout)
        ch.setLevel(level)
        ch.setFormatter(SnafflerConsoleFormatter())
        logger.addHandler(ch)

    if log_to_file and log_file_path:
        base = Path(log_file_path)
        base.parent.mkdir(parents=True, exist_ok=True)

        handlers = []

        if log_type == "all":
            handlers.append(_plain_file_handler(base.with_suffix(".log"), level))
            handlers.append(_json_file_handler(base.with_suffix(".json")))
            handlers.append(_tsv_file_handler(base.with_suffix(".tsv")))

        elif log_type == "json":
            handlers.append(_json_file_handler(base))

        elif log_type == "tsv":
            handlers.append(_tsv_file_handler(base))

        else:  # plain
            handlers.append(_plain_file_handler(base, level))

        for h in handlers:
            logger.addHandler(h)

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
    parts = [f"[{triage}]", f"[{rule_name}]"]

    if size is not None:
        parts.append(f"[{format_size(size)}]")
    if modified:
        parts.append(f"[mtime:{modified}]")

    parts.append(file_path)

    if match:
        parts.append(f"Match: {match}")
    if context:
        parts.append(f"Context: {context[:200]}...")

    message = " ".join(parts)

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


def print_completion_stats(start_time):
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
    logger.info("-" * 60)


def format_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}PB"
