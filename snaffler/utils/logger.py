"""
Logging utilities for Snaffler Linux
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class DataOnlyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return getattr(record, "is_data", False)


# Color codes for console output
class Colors:
    BLACK = '\033[90m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    GRAY = '\033[37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class SnafflerFormatter(logging.Formatter):
    """Custom formatter for Snaffler output"""

    LEVEL_COLORS = {
        'DEBUG': Colors.GRAY,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.RED + Colors.BOLD,
    }

    def __init__(self, use_colors=True):
        super().__init__()
        self.use_colors = use_colors

    def format(self, record):
        # Colorized console format
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        level = record.levelname
        message = record.getMessage()

        if self.use_colors and sys.stdout.isatty():
            color = self.LEVEL_COLORS.get(level, '')
            return f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {color}[{level}]{Colors.RESET} {message}"
        else:
            return f"[{timestamp}] [{level}] {message}"


class SnafflerJSONFormatter(logging.Formatter):
    """JSON formatter for file output"""

    def format(self, record):
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, 'file_path'):
            log_data['file_path'] = record.file_path
        if hasattr(record, 'triage'):
            log_data['triage'] = record.triage
        if hasattr(record, 'rule_name'):
            log_data['rule_name'] = record.rule_name
        if hasattr(record, 'match_context'):
            log_data['match_context'] = record.match_context

        return json.dumps(log_data)


def setup_logging(
        log_level: str = "info",
        log_to_file: bool = False,
        log_file_path: Optional[str] = None,
        log_to_console: bool = True,
        log_type: str = "plain"
) -> logging.Logger:
    """
    Setup logging configuration

    Args:
        log_level: Logging level (trace, debug, info, data)
        log_to_file: Whether to log to file
        log_file_path: Path to log file
        log_to_console: Whether to log to console
        log_type: Log format type (plain or json)

    Returns:
        Configured logger instance
    """
    # Map custom levels to logging levels
    level_map = {
        'trace': logging.DEBUG,
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'data': logging.WARNING,  # Only show results
    }

    level = level_map.get(log_level.lower(), logging.INFO)

    # Create logger
    logger = logging.getLogger('snaffler')
    logger.setLevel(logging.DEBUG)  # Capture everything, filter in handlers
    logger.handlers = []  # Clear existing handlers

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = SnafflerFormatter(use_colors=True)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_to_file and log_file_path:
        log_path = Path(log_file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file_path, mode='a')

        if log_level == "data":
            file_handler.setLevel(logging.DEBUG)
            file_handler.addFilter(DataOnlyFilter())
        else:
            file_handler.setLevel(level)

        if log_type == 'json':
            file_formatter = SnafflerJSONFormatter()
        else:
            file_formatter = SnafflerFormatter(use_colors=False)

        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def log_file_result(
        logger: logging.Logger,
        file_path: str,
        triage: str,
        rule_name: str,
        match: str = None,
        context: str = None,
        size: int = None,
        modified: str = None
):
    """
    Log a file result in Snaffler format

    Args:
        logger: Logger instance
        file_path: Path to the file
        triage: Triage level (Black, Red, Yellow, Green)
        rule_name: Name of the rule that matched
        match: The matched pattern/string
        context: Context around the match
        size: File size in bytes
        modified: Last modified timestamp
    """
    # Color map for triage levels
    triage_colors = {
        'Black': Colors.BLACK + Colors.BOLD,
        'Red': Colors.RED + Colors.BOLD,
        'Yellow': Colors.YELLOW + Colors.BOLD,
        'Green': Colors.GREEN,
        'Gray': Colors.GRAY,
    }

    color = triage_colors.get(triage, '')

    parts = [f"{color}[{triage}]{Colors.RESET}", f"[{rule_name}]"]

    if size:
        parts.append(f"[{format_size(size)}]")

    if modified:
        parts.append(f"[mtime:{modified}]")

    parts.append(f"{Colors.BOLD}{file_path}{Colors.RESET}")

    if match:
        parts.append(f"Match: {match}")

    if context:
        parts.append(f"Context: {context[:200]}...")

    message = " ".join(parts)

    # Create a log record with extra fields for JSON output
    extra = {
        'file_path': file_path,
        'triage': triage,
        'rule_name': rule_name,
        'is_data': True,
    }

    if match:
        extra['match'] = match
    if context:
        extra['match_context'] = context

    logger.warning(message, extra=extra)

def print_completion_stats(start_time):
    """Print completion statistics"""
    if not start_time:
        return

    logger = logging.getLogger('snaffler')
    end_time = datetime.now()
    duration = end_time - start_time

    total_seconds = int(duration.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    logger.info("-" * 60)
    logger.info(f"Started:  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")

    if hours > 0:
        logger.info(f"Duration: {hours}h {minutes}m {seconds}s")
    elif minutes > 0:
        logger.info(f"Duration: {minutes}m {seconds}s")
    else:
        logger.info(f"Duration: {seconds}s")

    logger.info("-" * 60)


def format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}PB"
