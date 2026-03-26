"""Hard-fail guard for unrecoverable OS errors (file descriptor exhaustion)."""

import errno
import sys

_FATAL_ERRNOS = frozenset({errno.EMFILE, errno.ENFILE})


def check_fatal_os_error(exc=None):
    """Abort if *exc* is an EMFILE / ENFILE OSError.

    Call at the top of any ``except Exception`` block on an I/O path.
    When *exc* is ``None``, the current exception is inspected via
    ``sys.exc_info()``.

    Raises ``SystemExit`` (a ``BaseException`` subclass) so it punches
    through every ``except Exception`` handler above us while still
    letting ``finally`` cleanup blocks run.
    """
    if exc is None:
        exc = sys.exc_info()[1]
    if isinstance(exc, OSError) and exc.errno in _FATAL_ERRNOS:
        raise SystemExit(
            f"FATAL: {exc.strerror} (errno {exc.errno}) — "
            f"file descriptor leak detected, aborting scan"
        ) from exc
