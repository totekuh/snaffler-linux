"""Test that -o writes to file while console output continues."""
import json
import subprocess
import sys


def test_dual_output_console_and_file(tmp_path):
    """When -o is given, both console and file should receive logs."""
    log_file = tmp_path / "output.log"

    result = subprocess.run(
        [
            sys.executable, "-m", "snaffler.cli.main",
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


def test_output_json_auto_format(tmp_path):
    """``-o output.json`` should auto-select JSON format."""
    log_file = tmp_path / "output.json"

    subprocess.run(
        [
            sys.executable, "-m", "snaffler.cli.main",
            "-q",
            "-u", "test",
            "-p", "test",
            "--unc", "//FAKE/SHARE",
            "-o", str(log_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    content = log_file.read_text()
    assert content.strip(), "Log file should not be empty"
    # Every non-empty line should be valid JSON
    for line in content.strip().splitlines():
        parsed = json.loads(line)
        assert "timestamp" in parsed


def test_output_tsv_auto_format(tmp_path):
    """``-o output.tsv`` should auto-select TSV format."""
    log_file = tmp_path / "output.tsv"

    subprocess.run(
        [
            sys.executable, "-m", "snaffler.cli.main",
            "-q",
            "-u", "test",
            "-p", "test",
            "--unc", "//FAKE/SHARE",
            "-o", str(log_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    content = log_file.read_text()
    assert content.strip(), "Log file should not be empty"
    # TSV lines should contain tabs
    for line in content.strip().splitlines():
        assert "\t" in line


def test_output_explicit_log_type_overrides_extension(tmp_path):
    """Explicit --log-type should override extension-based auto-detection."""
    log_file = tmp_path / "output.json"

    subprocess.run(
        [
            sys.executable, "-m", "snaffler.cli.main",
            "-q",
            "-u", "test",
            "-p", "test",
            "--unc", "//FAKE/SHARE",
            "-o", str(log_file),
            "--log-type", "plain",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    content = log_file.read_text()
    assert content.strip(), "Log file should not be empty"
    # Plain format uses [timestamp] [LEVEL] prefix, not JSON
    first_line = content.strip().splitlines()[0]
    assert first_line.startswith("["), f"Expected plain format, got: {first_line!r}"


def test_output_explicit_log_type_overrides_tsv_extension(tmp_path):
    """Explicit --log-type should override .tsv extension auto-detection."""
    log_file = tmp_path / "output.tsv"

    subprocess.run(
        [
            sys.executable, "-m", "snaffler.cli.main",
            "-q",
            "-u", "test",
            "-p", "test",
            "--unc", "//FAKE/SHARE",
            "-o", str(log_file),
            "--log-type", "plain",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    content = log_file.read_text()
    assert content.strip(), "Log file should not be empty"
    # Plain format uses [timestamp] [LEVEL] prefix, not TSV
    first_line = content.strip().splitlines()[0]
    assert first_line.startswith("["), f"Expected plain format, got: {first_line!r}"
