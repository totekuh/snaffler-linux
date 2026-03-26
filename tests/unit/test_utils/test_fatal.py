"""Tests for snaffler.utils.fatal — EMFILE/ENFILE hard-fail guard."""

import errno

import pytest

from snaffler.utils.fatal import check_fatal_os_error


class TestCheckFatalOsError:
    """check_fatal_os_error() must raise SystemExit on EMFILE/ENFILE only."""

    def test_emfile_raises_system_exit(self):
        exc = OSError(errno.EMFILE, "Too many open files")
        with pytest.raises(SystemExit, match="FATAL"):
            check_fatal_os_error(exc)

    def test_enfile_raises_system_exit(self):
        exc = OSError(errno.ENFILE, "Too many open files in system")
        with pytest.raises(SystemExit, match="FATAL"):
            check_fatal_os_error(exc)

    def test_enoent_passes_through(self):
        exc = OSError(errno.ENOENT, "No such file or directory")
        check_fatal_os_error(exc)  # should not raise

    def test_eacces_passes_through(self):
        exc = OSError(errno.EACCES, "Permission denied")
        check_fatal_os_error(exc)  # should not raise

    def test_econnrefused_passes_through(self):
        exc = OSError(errno.ECONNREFUSED, "Connection refused")
        check_fatal_os_error(exc)  # should not raise

    def test_non_oserror_passes_through(self):
        check_fatal_os_error(ValueError("something"))  # should not raise

    def test_none_exc_no_active_exception(self):
        check_fatal_os_error(None)  # should not raise (no active exception)

    def test_none_exc_uses_sys_exc_info(self):
        """When exc=None, inspects the current exception context."""
        with pytest.raises(SystemExit, match="FATAL"):
            try:
                raise OSError(errno.EMFILE, "Too many open files")
            except Exception:
                check_fatal_os_error()  # no arg — reads sys.exc_info()

    def test_system_exit_chains_original(self):
        """SystemExit.__cause__ should be the original OSError."""
        exc = OSError(errno.EMFILE, "Too many open files")
        with pytest.raises(SystemExit) as exc_info:
            check_fatal_os_error(exc)
        assert exc_info.value.__cause__ is exc

    def test_system_exit_bypasses_except_exception(self):
        """SystemExit must propagate through 'except Exception' blocks."""
        exc = OSError(errno.EMFILE, "Too many open files")
        with pytest.raises(SystemExit):
            try:
                check_fatal_os_error(exc)
            except Exception:
                pytest.fail("SystemExit was caught by 'except Exception'")

    def test_system_exit_allows_finally(self):
        """Finally blocks must still execute."""
        exc = OSError(errno.EMFILE, "Too many open files")
        finally_ran = False
        with pytest.raises(SystemExit):
            try:
                check_fatal_os_error(exc)
            finally:
                finally_ran = True
        assert finally_ran
