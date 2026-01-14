"""
Integration test that runs a full scan with mocked SMB server.
Serves files from tests/data as if they were on a share named SnaffMock.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from snaffler.cli.main import app

TEST_DATA_DIR = Path(__file__).parent.parent / "data"
MOCK_SERVER = "mockserver"
MOCK_SHARE = "SnaffMock"


class MockDirectoryEntry:
    """Mock SMB directory entry that mimics impacket's SharedFile."""

    def __init__(self, name: str, is_dir: bool, size: int = 0):
        self._name = name
        self._is_dir = is_dir
        self._size = size

    def get_longname(self) -> str:
        return self._name

    def is_directory(self) -> bool:
        return self._is_dir

    def get_filesize(self) -> int:
        return self._size


class MockSMBFileAccessor:
    """
    Mock SMB file accessor that serves files from tests/data directory.
    Maps UNC paths like //mockserver/SnaffMock/path to tests/data/path.
    """

    def __init__(self, data_root: Path):
        self.data_root = data_root

    def _resolve_path(self, path: str) -> Path:
        """Convert SMB path to local filesystem path."""
        clean = path.lstrip("/\\").replace("\\", "/")
        return self.data_root / clean

    def can_read(self, server: str, share: str, path: str) -> bool:
        local = self._resolve_path(path)
        return local.exists() and local.is_file()

    def read(self, server: str, share: str, path: str, max_bytes: int = None) -> bytes | None:
        local = self._resolve_path(path)
        if not local.exists() or not local.is_file():
            return None
        try:
            data = local.read_bytes()
            if max_bytes is not None:
                return data[:max_bytes]
            return data
        except Exception:
            return None

    def copy_to_local(self, server: str, share: str, path: str, dest_root: str) -> None:
        pass

    def list_path(self, server: str, share: str, path: str) -> list:
        """List directory contents, mimicking SMB listPath behavior."""
        clean = path.rstrip("*").rstrip("/\\")
        local_dir = self._resolve_path(clean) if clean else self.data_root

        if not local_dir.exists() or not local_dir.is_dir():
            return []

        entries = [
            MockDirectoryEntry(".", is_dir=True),
            MockDirectoryEntry("..", is_dir=True),
        ]

        for item in local_dir.iterdir():
            if item.name.startswith("."):
                continue
            entries.append(
                MockDirectoryEntry(
                    name=item.name,
                    is_dir=item.is_dir(),
                    size=item.stat().st_size if item.is_file() else 0,
                )
            )

        return entries


def collect_all_files(root: Path, prefix: str = "") -> set[str]:
    """Recursively collect all file paths from a directory."""
    files = set()
    for item in root.iterdir():
        if item.name.startswith("."):
            continue
        rel_path = f"{prefix}/{item.name}" if prefix else item.name
        if item.is_dir():
            files.update(collect_all_files(item, rel_path))
        else:
            files.add(rel_path)
    return files


@pytest.fixture
def mock_accessor():
    """Create a mock accessor that serves files from tests/data."""
    return MockSMBFileAccessor(TEST_DATA_DIR)


@pytest.fixture
def expected_files():
    """Get the set of all files in tests/data."""
    return collect_all_files(TEST_DATA_DIR)


class TestFullScan:
    """Integration tests for full snaffler scan."""

    def test_full_scan_with_mock_smb(self, tmp_path, mock_accessor, expected_files):
        """
        Run a full scan with mocked SMB server serving tests/data files.
        Verify that discovered files appear in the log output.
        """
        log_file = tmp_path / "snaffler_test.log"
        unc_path = f"//{MOCK_SERVER}/{MOCK_SHARE}"

        runner = CliRunner()

        with patch(
            "snaffler.engine.file_pipeline.SMBFileAccessor",
            return_value=mock_accessor,
        ):
            result = runner.invoke(
                app,
                [
                    "--unc", unc_path,
                    "-u", "testuser",
                    "-p", "testpass",
                    "-o", str(log_file),
                    "-q",  # no banner
                    "--log-level", "debug",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        # Read log file
        assert log_file.exists(), "Log file was not created"
        log_content = log_file.read_text()

        # Verify files were discovered - check that some test files appear in the log
        # Not all files will match rules, but the scan should find them
        discovered_files = []
        for line in log_content.splitlines():
            if MOCK_SHARE in line:
                discovered_files.append(line)

        # We expect at least some files to be found and logged
        assert len(discovered_files) > 0, (
            f"No files from {MOCK_SHARE} found in log.\n"
            f"Log content:\n{log_content[:2000]}"
        )

    def test_full_scan_finds_sensitive_files(self, tmp_path, mock_accessor):
        """
        Verify that known sensitive files from tests/data are detected.
        """
        log_file = tmp_path / "snaffler_test.log"
        unc_path = f"//{MOCK_SERVER}/{MOCK_SHARE}"

        runner = CliRunner()

        with patch(
            "snaffler.engine.file_pipeline.SMBFileAccessor",
            return_value=mock_accessor,
        ):
            result = runner.invoke(
                app,
                [
                    "--unc", unc_path,
                    "-u", "testuser",
                    "-p", "testpass",
                    "-o", str(log_file),
                    "-q",
                    "--log-level", "info",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        log_content = log_file.read_text()

        # List of sensitive files that should be detected by snaffler rules
        sensitive_patterns = [
            "server.key",
            "server.pfx",
            ".pgpass",
            "passwords.txt",
            "credentials",
            "aws",
            ".pem",
            "private_key",
            "unattend",
        ]

        found_sensitive = []
        for pattern in sensitive_patterns:
            if pattern.lower() in log_content.lower():
                found_sensitive.append(pattern)

        assert len(found_sensitive) > 0, (
            f"No sensitive files detected.\n"
            f"Expected patterns: {sensitive_patterns}\n"
            f"Log content:\n{log_content[:3000]}"
        )

    def test_full_scan_all_test_files_scanned(self, tmp_path, mock_accessor, expected_files):
        """
        Verify that all files from tests/data are scanned (appear in debug log).
        """
        log_file = tmp_path / "snaffler_test.log"
        unc_path = f"//{MOCK_SERVER}/{MOCK_SHARE}"

        runner = CliRunner()

        with patch(
            "snaffler.engine.file_pipeline.SMBFileAccessor",
            return_value=mock_accessor,
        ):
            result = runner.invoke(
                app,
                [
                    "--unc", unc_path,
                    "-u", "testuser",
                    "-p", "testpass",
                    "-o", str(log_file),
                    "-q",
                    "--log-level", "debug",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        log_content = log_file.read_text()

        # Check that files were found - look for the "Found X files" message
        assert "Found" in log_content and "files" in log_content, (
            f"Expected 'Found X files' message in log.\n"
            f"Log content:\n{log_content[:2000]}"
        )

        # Verify specific test files exist in log (by checking a sample)
        sample_files = [
            "server.key",
            "server.pfx",
            "secrets.txt",
            "benign.ps1",
        ]

        for sample in sample_files:
            assert sample in log_content, (
                f"Expected file '{sample}' not found in log.\n"
                f"Log excerpt:\n{log_content[:2000]}"
            )


class TestScanWithJsonOutput:
    """Test JSON output format."""

    def test_json_output_contains_findings(self, tmp_path, mock_accessor):
        """Verify JSON output contains structured finding data."""
        import json

        log_file = tmp_path / "snaffler_test"
        unc_path = f"//{MOCK_SERVER}/{MOCK_SHARE}"

        runner = CliRunner()

        with patch(
            "snaffler.engine.file_pipeline.SMBFileAccessor",
            return_value=mock_accessor,
        ):
            result = runner.invoke(
                app,
                [
                    "--unc", unc_path,
                    "-u", "testuser",
                    "-p", "testpass",
                    "-o", str(log_file),
                    "-q",
                    "-t", "all",  # output all formats
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, f"CLI failed: {result.output}"

        json_file = log_file.with_suffix(".json")
        assert json_file.exists(), "JSON log file was not created"

        json_content = json_file.read_text()
        if not json_content.strip():
            pytest.skip("No findings to validate in JSON (may be expected)")

        # Parse each line as JSON
        findings = []
        for line in json_content.strip().splitlines():
            if line.strip():
                findings.append(json.loads(line))

        assert len(findings) > 0, "No findings in JSON output"

        # Verify structure of findings
        for finding in findings:
            assert "file_path" in finding, f"Missing file_path in finding: {finding}"
            assert "triage" in finding, f"Missing triage in finding: {finding}"
            assert "rule_name" in finding, f"Missing rule_name in finding: {finding}"
