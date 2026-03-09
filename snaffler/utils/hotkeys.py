"""
Runtime hotkey listener for switching log levels during a scan.

Press 'd' → DEBUG, 'i' → INFO.  Skipped when stdin is not a TTY.
"""
import logging
import select
import sys
import threading

_thread: threading.Thread | None = None
_stop_event: threading.Event | None = None
_original_termios = None


def _get_console_handler() -> logging.StreamHandler | None:
    """Return the first StreamHandler on the 'snaffler' logger."""
    for h in logging.getLogger("snaffler").handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            return h
    return None


def _change_log_level(key: str) -> None:
    """Apply a log level change for a recognized key."""
    handler = _get_console_handler()
    if handler is None:
        return
    key = key.lower()
    if key == "d":
        handler.setLevel(logging.DEBUG)
        logging.getLogger("snaffler").info("Log level \u2192 DEBUG (press 'i' for INFO)")
    elif key == "i":
        handler.setLevel(logging.INFO)
        logging.getLogger("snaffler").info("Log level \u2192 INFO (press 'd' for DEBUG)")


def _listener(stop: threading.Event) -> None:
    """Poll stdin for single keypresses until *stop* is set."""
    while not stop.is_set():
        ready, _, _ = select.select([sys.stdin], [], [], 0.5)
        if ready:
            try:
                ch = sys.stdin.read(1)
            except Exception:
                break
            if ch:
                _change_log_level(ch)


def start_hotkey_listener(stop_event: threading.Event) -> None:
    """Start the hotkey listener daemon thread (no-op if stdin is not a TTY)."""
    global _thread, _stop_event, _original_termios

    if not sys.stdin.isatty():
        return

    try:
        import termios
        import tty
    except ImportError:
        return

    try:
        _original_termios = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
    except Exception:
        _original_termios = None
        return

    _stop_event = stop_event
    _thread = threading.Thread(target=_listener, args=(stop_event,), daemon=True)
    _thread.start()


def stop_hotkey_listener() -> None:
    """Stop the listener and restore original terminal settings."""
    global _thread, _stop_event, _original_termios

    if _stop_event is not None:
        _stop_event.set()

    # Restore terminal FIRST so subsequent output prints cleanly.
    if _original_termios is not None:
        try:
            import termios
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, _original_termios)
        except Exception:
            pass
        _original_termios = None

    if _thread is not None:
        _thread.join(timeout=2)
        _thread = None

    _stop_event = None
