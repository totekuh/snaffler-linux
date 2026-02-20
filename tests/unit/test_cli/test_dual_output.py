"""Test that -o writes to file while console output continues."""
import subprocess
import sys


def test_dual_output_console_and_file(tmp_path):
    """When -o is given, both console and file should receive logs."""
    log_file = tmp_path / "output.log"

    result = subprocess.run(
        [
            sys.executable, "-m", "snaffler.cli.main",
            "run",
            "-q",                          # no banner
            "-u", "test",
            "-p", "test",
            "--unc", "//FAKE/SHARE",
            "-o", str(log_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    # The run will fail (can't connect to FAKE) but should produce logs
    console = result.stdout + result.stderr

    assert "Starting Snaffler" in console, (
        f"Console should contain log output, got: {console!r}"
    )

    file_content = log_file.read_text()
    assert "Starting Snaffler" in file_content, (
        f"Log file should contain output, got: {file_content!r}"
    )


def test_output_file_only_no_console_loss(tmp_path):
    """Console should still show progress/error info alongside file output."""
    log_file = tmp_path / "output.log"

    result = subprocess.run(
        [
            sys.executable, "-m", "snaffler.cli.main",
            "run",
            "-q",
            "-u", "test",
            "-p", "test",
            "--unc", "//FAKE/SHARE",
            "-o", str(log_file),
            "--log-level", "debug",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    console = result.stdout + result.stderr

    # Both should have content
    assert len(console.strip()) > 0, "Console should not be empty"
    assert log_file.stat().st_size > 0, "Log file should not be empty"
