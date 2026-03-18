"""Tests for --grab bulk download mode."""
import os
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from snaffler.cli.main import app

runner = CliRunner()


def base_args():
    return ["--no-banner", "--log-level", "info"]


def test_grab_requires_snaffle_path():
    result = runner.invoke(
        app,
        base_args() + ["--grab"],
        input="//HOST/SHARE/file.txt\n",
    )
    assert result.exit_code != 0
    assert "--grab requires -m" in result.output


def test_grab_mutually_exclusive_with_unc():
    result = runner.invoke(
        app,
        base_args() + ["--grab", "-m", "/tmp/loot", "--unc", "//HOST/SHARE"],
        input="//HOST/SHARE/file.txt\n",
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_grab_mutually_exclusive_with_domain():
    result = runner.invoke(
        app,
        base_args() + ["--grab", "-m", "/tmp/loot", "-d", "corp.local"],
        input="//HOST/SHARE/file.txt\n",
    )
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_grab_empty_stdin():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--grab", "-m", "/tmp/loot"],
            input="",
        )
    assert result.exit_code != 0
    assert "No file paths" in result.output


def test_grab_smb_paths(tmp_path):
    dest = tmp_path / "loot"

    mock_accessor = MagicMock()

    def fake_copy(file_path, dest_root):
        # Create the file so the existence check passes
        from snaffler.utils.path_utils import parse_unc_path
        from pathlib import Path
        parsed = parse_unc_path(file_path)
        if parsed:
            server, share, smb_path, _, _ = parsed
            clean = smb_path.lstrip("\\/").replace("\\", "/")
            local = Path(dest_root) / server / share / clean
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(b"fake content")

    mock_accessor.copy_to_local.side_effect = fake_copy

    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"), \
            patch("snaffler.accessors.smb_file_accessor.SMBFileAccessor", return_value=mock_accessor):
        result = runner.invoke(
            app,
            base_args() + ["--grab", "-m", str(dest)],
            input="//DC01/SYSVOL/scripts/login.bat\n//DC01/SYSVOL/scripts/map.ps1\n",
        )

    assert result.exit_code == 0
    assert "Grabbing 2 files" in result.output
    assert "2 downloaded, 0 failed" in result.output
    assert mock_accessor.copy_to_local.call_count == 2


def test_grab_local_paths(tmp_path):
    dest = tmp_path / "loot"
    # Create source files
    src = tmp_path / "source"
    src.mkdir()
    (src / "secret.txt").write_text("password123")

    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--grab", "-m", str(dest)],
            input=f"{src}/secret.txt\n",
        )

    assert result.exit_code == 0
    assert "1 downloaded, 0 failed" in result.output


def test_grab_counts_failed_downloads(tmp_path):
    dest = tmp_path / "loot"

    mock_accessor = MagicMock()
    # copy_to_local does nothing — file won't exist → counted as failed
    mock_accessor.copy_to_local.return_value = None

    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"), \
            patch("snaffler.accessors.smb_file_accessor.SMBFileAccessor", return_value=mock_accessor):
        result = runner.invoke(
            app,
            base_args() + ["--grab", "-m", str(dest)],
            input="//HOST/SHARE/missing.txt\n",
        )

    assert result.exit_code == 0
    assert "0 downloaded, 1 failed" in result.output


def test_grab_mixed_protocols(tmp_path):
    dest = tmp_path / "loot"

    mock_smb = MagicMock()
    mock_ftp = MagicMock()

    # SMB accessor — simulate success
    def smb_copy(file_path, dest_root):
        from snaffler.utils.path_utils import parse_unc_path
        from pathlib import Path
        parsed = parse_unc_path(file_path)
        if parsed:
            server, share, smb_path, _, _ = parsed
            clean = smb_path.lstrip("\\/").replace("\\", "/")
            local = Path(dest_root) / server / share / clean
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(b"data")

    mock_smb.copy_to_local.side_effect = smb_copy

    # FTP accessor — simulate success
    def ftp_copy(file_path, dest_root):
        from snaffler.discovery.ftp_tree_walker import parse_ftp_url
        from pathlib import Path
        parsed = parse_ftp_url(file_path)
        if parsed:
            host, _port, remote = parsed
            local = Path(dest_root) / host / remote.lstrip("/")
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(b"data")

    mock_ftp.copy_to_local.side_effect = ftp_copy

    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"), \
            patch("snaffler.accessors.smb_file_accessor.SMBFileAccessor", return_value=mock_smb), \
            patch("snaffler.accessors.ftp_file_accessor.FTPFileAccessor", return_value=mock_ftp):
        result = runner.invoke(
            app,
            base_args() + ["--grab", "-m", str(dest)],
            input="//DC01/SHARE/file.txt\nftp://ftpserver/pub/data.csv\n",
        )

    assert result.exit_code == 0
    assert "Grabbing 2 files" in result.output
    assert "2 downloaded, 0 failed" in result.output
    assert mock_smb.copy_to_local.call_count == 1
    assert mock_ftp.copy_to_local.call_count == 1


def test_grab_skips_blank_lines(tmp_path):
    dest = tmp_path / "loot"

    mock_accessor = MagicMock()

    def fake_copy(file_path, dest_root):
        from snaffler.utils.path_utils import parse_unc_path
        from pathlib import Path
        parsed = parse_unc_path(file_path)
        if parsed:
            server, share, smb_path, _, _ = parsed
            clean = smb_path.lstrip("\\/").replace("\\", "/")
            local = Path(dest_root) / server / share / clean
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(b"data")

    mock_accessor.copy_to_local.side_effect = fake_copy

    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"), \
            patch("snaffler.accessors.smb_file_accessor.SMBFileAccessor", return_value=mock_accessor):
        result = runner.invoke(
            app,
            base_args() + ["--grab", "-m", str(dest)],
            input="\n//HOST/SHARE/file.txt\n\n\n",
        )

    assert result.exit_code == 0
    assert "Grabbing 1 files" in result.output
    assert "1 downloaded" in result.output
