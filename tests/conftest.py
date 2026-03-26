"""Shared test configuration factories.

Provides ``make_engine_cfg()`` and ``make_scanner_cfg()`` used across
unit and integration tests.  Import directly::

    from tests.conftest import make_engine_cfg, make_scanner_cfg

Autouse fixtures (``_skip_auth_check``, ``_reset_finding_store``) remain
in their respective test modules since they are only needed by a subset
of tests.
"""

from unittest.mock import MagicMock


def make_engine_cfg(**overrides):
    """Return a MagicMock ``SnafflerConfiguration`` suitable for engine tests.

    All fields that runner / pipeline / share pipeline code accesses are
    pre-set to safe defaults. Pass keyword arguments to override any field,
    using dotted-path syntax collapsed to double-underscore::

        cfg = make_engine_cfg(targets__unc_targets=["//HOST/SHARE"])
    """
    cfg = MagicMock()

    # ---------- state ----------
    cfg.state.state_db = ":memory:"

    # ---------- targets ----------
    cfg.targets.unc_targets = []
    cfg.targets.computer_targets = []
    cfg.targets.local_targets = []
    cfg.targets.ftp_targets = []
    cfg.targets.shares_only = False
    cfg.targets.rescan_unreadable = False
    cfg.targets.share_filter = []
    cfg.targets.exclude_share = []
    cfg.targets.exclude_unc = []
    cfg.targets.exclusions = []

    # ---------- auth ----------
    cfg.auth.domain = None

    # ---------- advanced ----------
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2
    cfg.advanced.dns_threads = 4
    cfg.advanced.max_tree_threads_per_share = 0  # unlimited

    # ---------- rules ----------
    cfg.rules.file = []
    cfg.rules.content = []
    cfg.rules.postmatch = []

    # ---------- scanning ----------
    cfg.scanning.max_depth = None
    cfg.scanning.snaffle = False
    cfg.scanning.snaffle_path = None
    cfg.scanning.max_file_bytes = 1024 * 1024

    # ---------- web ----------
    cfg.web.enabled = False

    # ---------- apply overrides ----------
    for key, value in overrides.items():
        parts = key.split("__")
        obj = cfg
        for part in parts[:-1]:
            obj = getattr(obj, part)
        setattr(obj, parts[-1], value)

    return cfg


def make_scanner_cfg(match_filter=None, max_read=1024 * 1024):
    """Return a MagicMock ``SnafflerConfiguration`` suitable for FileScanner tests.

    Pre-sets all ``cfg.scanning.*`` fields that ``FileScanner.__init__``
    accesses.
    """
    cfg = MagicMock()
    cfg.scanning.min_interest = 0
    cfg.scanning.max_read_bytes = max_read
    cfg.scanning.max_file_bytes = max_read
    cfg.scanning.match_context_bytes = 20
    cfg.scanning.snaffle = False
    cfg.scanning.snaffle_path = None
    cfg.scanning.cert_passwords = []
    cfg.scanning.match_filter = match_filter
    return cfg
