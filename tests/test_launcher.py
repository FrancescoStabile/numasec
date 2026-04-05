"""Tests for numasec.launcher — smart TUI binary management."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from numasec.launcher import (
    _get_archive_ext,
    _get_download_url,
    _get_platform_target,
    _get_version,
    _needs_download,
    main,
)


class TestGetVersion:
    def test_returns_string(self):
        v = _get_version()
        assert isinstance(v, str)
        assert len(v) > 0

    def test_matches_init(self):
        from numasec import __version__

        v = _get_version()
        assert v == __version__


class TestGetPlatformTarget:
    @patch("numasec.launcher.platform")
    def test_linux_x64(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.machine.return_value = "x86_64"
        assert _get_platform_target() == "numasec-linux-x64"

    @patch("numasec.launcher.platform")
    def test_linux_arm64(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.machine.return_value = "aarch64"
        assert _get_platform_target() == "numasec-linux-arm64"

    @patch("numasec.launcher.platform")
    def test_darwin_arm64(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        mock_platform.machine.return_value = "arm64"
        assert _get_platform_target() == "numasec-darwin-arm64"

    @patch("numasec.launcher.platform")
    def test_darwin_x64(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        mock_platform.machine.return_value = "x86_64"
        assert _get_platform_target() == "numasec-darwin-x64"

    @patch("numasec.launcher.platform")
    def test_windows_x64(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        mock_platform.machine.return_value = "AMD64"
        assert _get_platform_target() == "numasec-windows-x64"

    @patch("numasec.launcher.platform")
    def test_unsupported_raises(self, mock_platform):
        mock_platform.system.return_value = "FreeBSD"
        mock_platform.machine.return_value = "mips"
        with pytest.raises(RuntimeError, match="Unsupported platform"):
            _get_platform_target()


class TestGetArchiveExt:
    def test_linux_targz(self):
        assert _get_archive_ext("numasec-linux-x64") == ".tar.gz"

    def test_darwin_targz(self):
        assert _get_archive_ext("numasec-darwin-arm64") == ".tar.gz"

    def test_windows_zip(self):
        assert _get_archive_ext("numasec-windows-x64") == ".zip"


class TestGetDownloadUrl:
    def test_default_url(self):
        url = _get_download_url("4.0.0", "numasec-linux-x64")
        assert url == "https://github.com/FrancescoStabile/numasec/releases/download/v4.0.0/numasec-linux-x64.tar.gz"

    def test_darwin_url(self):
        url = _get_download_url("4.1.0", "numasec-darwin-arm64")
        assert url == "https://github.com/FrancescoStabile/numasec/releases/download/v4.1.0/numasec-darwin-arm64.tar.gz"

    def test_windows_url(self):
        url = _get_download_url("4.0.0", "numasec-windows-x64")
        assert url == "https://github.com/FrancescoStabile/numasec/releases/download/v4.0.0/numasec-windows-x64.zip"

    def test_custom_base_url(self):
        with patch.dict(os.environ, {"NUMASEC_DOWNLOAD_URL": "https://mirror.example.com/releases"}):
            url = _get_download_url("4.0.0", "numasec-linux-x64")
            assert url.startswith("https://mirror.example.com/releases/")


class TestNeedsDownload:
    def test_no_binary(self, tmp_path):
        with patch("numasec.launcher.BIN_DIR", tmp_path):
            assert _needs_download("4.0.0") is True

    def test_no_version_file(self, tmp_path):
        (tmp_path / "numasec-tui").write_text("binary")
        with patch("numasec.launcher.BIN_DIR", tmp_path), patch(
            "numasec.launcher.TUI_BINARY_NAME", "numasec-tui"
        ), patch("numasec.launcher.VERSION_FILE_NAME", ".tui-version"):
            assert _needs_download("4.0.0") is True

    def test_version_matches(self, tmp_path):
        (tmp_path / "numasec-tui").write_text("binary")
        (tmp_path / ".tui-version").write_text("4.0.0")
        with patch("numasec.launcher.BIN_DIR", tmp_path), patch(
            "numasec.launcher.TUI_BINARY_NAME", "numasec-tui"
        ), patch("numasec.launcher.VERSION_FILE_NAME", ".tui-version"):
            assert _needs_download("4.0.0") is False

    def test_version_mismatch(self, tmp_path):
        (tmp_path / "numasec-tui").write_text("binary")
        (tmp_path / ".tui-version").write_text("3.9.0")
        with patch("numasec.launcher.BIN_DIR", tmp_path), patch(
            "numasec.launcher.TUI_BINARY_NAME", "numasec-tui"
        ), patch("numasec.launcher.VERSION_FILE_NAME", ".tui-version"):
            assert _needs_download("4.0.0") is True


class TestMainEntryPoint:
    """Test the main() dispatch logic (mocked subprocess/download)."""

    @patch("numasec.launcher._get_version", return_value="4.0.0")
    def test_version_flag(self, mock_ver, capsys):
        with patch("sys.argv", ["numasec", "--version"]):
            main()
        out = capsys.readouterr().out
        assert "numasec 4.0.0" in out

    @patch("numasec.launcher._run_mcp_server")
    def test_mcp_flag_delegates(self, mock_mcp):
        with patch("sys.argv", ["numasec", "--mcp"]):
            main()
        mock_mcp.assert_called_once()

    @patch("numasec.launcher._run_mcp_server")
    def test_mcp_http_flag_delegates(self, mock_mcp):
        with patch("sys.argv", ["numasec", "--mcp-http"]):
            main()
        mock_mcp.assert_called_once()

    @patch("numasec.launcher._run_mcp_server")
    def test_pipe_stdin_delegates_to_mcp(self, mock_mcp):
        with patch("sys.argv", ["numasec"]), patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            main()
        mock_mcp.assert_called_once()

    @patch("numasec.launcher._run_mcp_server")
    def test_mcp_transport_env_delegates(self, mock_mcp):
        with patch("sys.argv", ["numasec"]), patch.dict(os.environ, {"MCP_TRANSPORT": "stdio"}):
            main()
        mock_mcp.assert_called_once()

    @patch("numasec.launcher._launch_tui", return_value=0)
    @patch("numasec.launcher._needs_download", return_value=False)
    @patch("numasec.launcher._get_version", return_value="4.0.0")
    def test_tty_launches_tui(self, mock_ver, mock_needs, mock_launch):
        with patch("sys.argv", ["numasec"]), patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
        mock_launch.assert_called_once_with([])

    @patch("numasec.launcher.download_tui")
    @patch("numasec.launcher._launch_tui", return_value=0)
    @patch("numasec.launcher._needs_download", return_value=True)
    @patch("numasec.launcher._get_version", return_value="4.0.0")
    def test_tty_downloads_when_needed(self, mock_ver, mock_needs, mock_launch, mock_dl):
        with patch("sys.argv", ["numasec"]), patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with pytest.raises(SystemExit):
                main()
        mock_dl.assert_called_once_with("4.0.0")
        mock_launch.assert_called_once()

    @patch("numasec.launcher._run_mcp_server")
    @patch("numasec.launcher.download_tui", side_effect=RuntimeError("network error"))
    @patch("numasec.launcher._needs_download", return_value=True)
    @patch("numasec.launcher._get_version", return_value="4.0.0")
    def test_download_failure_falls_back_to_mcp(self, mock_ver, mock_needs, mock_dl, mock_mcp):
        with patch("sys.argv", ["numasec"]), patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            main()
        mock_mcp.assert_called_once()
