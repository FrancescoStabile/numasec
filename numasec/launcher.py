"""numasec — Smart launcher with TUI binary management.

When installed via pip, auto-detects whether the user is in an interactive
terminal (launches TUI) or connected via a pipe (starts MCP server).
Downloads the pre-compiled TUI binary on first run from GitHub Releases.

Usage:
    numasec              # Interactive: TUI | Pipe: MCP server
    numasec --mcp        # MCP server mode (stdio, explicit)
    numasec --mcp-http   # MCP server mode (HTTP)
    numasec --upgrade-tui  # Force re-download TUI binary
    numasec --version    # Show version info
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

GITHUB_REPO = "FrancescoStabile/numasec"
NUMASEC_DIR = Path.home() / ".numasec"
BIN_DIR = NUMASEC_DIR / "bin"
TUI_BINARY_NAME = "numasec-tui"
VERSION_FILE_NAME = ".tui-version"

_MCP_FLAGS = {"--mcp", "--mcp-http"}


def _get_version() -> str:
    """Get the installed numasec package version."""
    try:
        from importlib.metadata import version

        return version("numasec")
    except Exception:
        from numasec import __version__

        return __version__


def _get_platform_target() -> str:
    """Detect the current platform and return the build target name.

    Raises RuntimeError if the platform is unsupported.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    arch_map = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }

    os_name = os_map.get(system)
    arch_name = arch_map.get(machine)

    if not os_name or not arch_name:
        raise RuntimeError(
            f"Unsupported platform: {system}/{machine}. "
            f"Use 'numasec --mcp' for MCP server mode, "
            f"or install from source with install.sh"
        )

    return f"numasec-{os_name}-{arch_name}"


def _get_archive_ext(target: str) -> str:
    """Return the archive extension for the given target."""
    return ".tar.gz" if "linux" in target or "darwin" in target else ".zip"


def _get_download_url(version: str, target: str) -> str:
    """Build the GitHub Release download URL."""
    base = os.environ.get("NUMASEC_DOWNLOAD_URL", f"https://github.com/{GITHUB_REPO}/releases/download")
    ext = _get_archive_ext(target)
    return f"{base}/v{version}/{target}{ext}"


def _progress_hook(block_num: int, block_size: int, total_size: int) -> None:
    """Display download progress."""
    if total_size <= 0:
        downloaded = block_num * block_size
        sys.stdout.write(f"\r  Downloaded {downloaded / 1024 / 1024:.1f} MB...")
        sys.stdout.flush()
        return

    downloaded = min(block_num * block_size, total_size)
    pct = downloaded * 100 / total_size
    bar_len = 30
    filled = int(bar_len * downloaded / total_size)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r  [{bar}] {pct:.0f}% ({downloaded / 1024 / 1024:.1f} MB)")
    sys.stdout.flush()
    if downloaded >= total_size:
        sys.stdout.write("\n")
        sys.stdout.flush()


def _install_binary(binary_path: Path, version: str) -> None:
    """Install a TUI binary to the standard location."""
    tui_path = BIN_DIR / TUI_BINARY_NAME
    version_path = BIN_DIR / VERSION_FILE_NAME

    if tui_path.exists():
        tui_path.unlink()

    shutil.copy2(binary_path, tui_path)
    tui_path.chmod(tui_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    version_path.write_text(version)
    print(f"  ✓ Installed TUI binary to {tui_path}")


def _extract_binary(archive: Path, extract_dir: Path, is_targz: bool) -> Path:
    """Extract the archive and return the path to the numasec binary."""
    if is_targz:
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(extract_dir, filter="data")
    else:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(extract_dir)

    # Find the binary — it might be at the root or inside a subdirectory
    for name in ("numasec", "numasec.exe"):
        candidate = extract_dir / name
        if candidate.exists():
            return candidate

    # Search recursively
    candidates = [p for p in extract_dir.rglob("numasec*") if p.is_file() and "." not in p.name]
    if not candidates:
        candidates = list(extract_dir.rglob("numasec*"))
    if candidates:
        return candidates[0]

    raise RuntimeError("TUI binary not found in downloaded archive")


def download_tui(version: str) -> None:
    """Download and install the TUI binary from GitHub Releases."""
    target = _get_platform_target()
    url = _get_download_url(version, target)
    is_targz = url.endswith(".tar.gz")

    BIN_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\n  Downloading numasec TUI v{version} ({target})...")
    print(f"  From: {url}\n")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive_name = "tui.tar.gz" if is_targz else "tui.zip"
        archive = tmp_path / archive_name

        try:
            urllib.request.urlretrieve(url, archive, reporthook=_progress_hook)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Fallback: try raw binary (legacy release format)
                raw_url = url.rsplit(".", 2)[0] if is_targz else url.rsplit(".", 1)[0]
                raw_binary = tmp_path / "numasec"
                try:
                    urllib.request.urlretrieve(raw_url, raw_binary, reporthook=_progress_hook)
                    _install_binary(raw_binary, version)
                    return
                except urllib.error.HTTPError:
                    pass

                raise RuntimeError(
                    f"TUI binary not found for v{version} ({target}).\n"
                    f"  URL: {url}\n"
                    f"  This version may not have pre-built binaries.\n\n"
                    f"  Alternatives:\n"
                    f"    curl -fsSL https://raw.githubusercontent.com/{GITHUB_REPO}/main/install.sh | bash\n"
                    f"    numasec --mcp  (MCP server mode, no TUI)"
                ) from e
            raise

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        binary = _extract_binary(archive, extract_dir, is_targz)
        _install_binary(binary, version)


def _needs_download(version: str) -> bool:
    """Check if TUI binary needs to be downloaded or updated."""
    tui_path = BIN_DIR / TUI_BINARY_NAME
    version_path = BIN_DIR / VERSION_FILE_NAME

    if not tui_path.exists():
        return True
    if not version_path.exists():
        return True

    installed = version_path.read_text().strip()
    return installed != version


def _launch_tui(extra_args: list[str]) -> int:
    """Launch the TUI binary, passing the Python path via env."""
    tui_path = BIN_DIR / TUI_BINARY_NAME

    env = os.environ.copy()
    env["NUMASEC_PYTHON_PATH"] = sys.executable
    env["NUMASEC_INSTALL_MODE"] = "pip"

    result = subprocess.run([str(tui_path), *extra_args], env=env)
    return result.returncode


def _run_mcp_server() -> None:
    """Delegate to the MCP server entry point."""
    from numasec.__main__ import main as mcp_main

    mcp_main()


def main() -> None:
    """Entry point for the ``numasec`` console script.

    Auto-detects the execution context:
    - Interactive terminal (TTY) → launch TUI
    - Pipe / non-TTY (MCP client) → start MCP server
    - Explicit flags (--mcp, --mcp-http) → MCP server
    """
    args = sys.argv[1:]

    # --version: show package + TUI info
    if "--version" in args:
        version = _get_version()
        print(f"numasec {version}")
        tui_path = BIN_DIR / TUI_BINARY_NAME
        version_path = BIN_DIR / VERSION_FILE_NAME
        if tui_path.exists() and version_path.exists():
            tui_ver = version_path.read_text().strip()
            print(f"TUI binary: v{tui_ver} ({tui_path})")
        else:
            print("TUI binary: not installed (will download on first run)")
        return

    # Explicit MCP flags → MCP server
    if _MCP_FLAGS & set(args) or os.environ.get("MCP_TRANSPORT"):
        _run_mcp_server()
        return

    # Non-interactive (pipe) → MCP server
    if not sys.stdin.isatty():
        _run_mcp_server()
        return

    # --- Interactive terminal: launch TUI ---

    version = _get_version()

    # --upgrade-tui: force re-download
    if "--upgrade-tui" in args:
        args = [a for a in args if a != "--upgrade-tui"]
        print(f"  Upgrading TUI binary to v{version}...")
        try:
            download_tui(version)
        except Exception as e:
            print(f"\n  ✗ Failed to download TUI binary: {e}\n", file=sys.stderr)
            sys.exit(1)
        if not args:
            return

    # Download TUI if missing or outdated
    if _needs_download(version):
        try:
            download_tui(version)
        except Exception as e:
            print(f"\n  ✗ Failed to download TUI binary: {e}\n", file=sys.stderr)
            print("  Falling back to MCP server mode.\n", file=sys.stderr)
            _run_mcp_server()
            return

    sys.exit(_launch_tui(args))


if __name__ == "__main__":
    main()
