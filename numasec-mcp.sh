#!/usr/bin/env bash
# NumaSec MCP entry point for external clients (Cursor, Claude Desktop, VS Code).
#
# Strategy: Two-stage launch.
#   Stage 1 (bash): Sanitize the environment — unset PYTHONHOME, PYTHONPATH,
#     VIRTUAL_ENV which editors like Cursor inject and which break venv Python.
#   Stage 2 (python): Launch the venv Python directly with explicit sys.path
#     covering both src/ (editable install) and site-packages (dependencies).
#
# This survives any combination of polluted environment variables.

# --- Stage 1: Sanitize ---
unset PYTHONHOME PYTHONPATH VIRTUAL_ENV CONDA_PREFIX

# --- Stage 2: Launch ---
# Derive base directory from script location (works for any user/install)
_BASE="$(cd "$(dirname "$0")" && pwd)"
_PYTHON="${_BASE}/.venv/bin/python3"

# Fallback: if venv python doesn't exist, try system python
if [ ! -x "$_PYTHON" ]; then
    _PYTHON="$(command -v python3 2>/dev/null || echo python3)"
fi

exec "$_PYTHON" -c '
import sys, os, glob
_BASE = os.path.dirname(os.path.abspath("'"$_BASE"'".replace("\x27", "\""))) if False else "'"$_BASE"'"
for p in [os.path.join(_BASE, "src")] + glob.glob(os.path.join(_BASE, ".venv/lib/python*/site-packages")):
    if p not in sys.path:
        sys.path.insert(0, p)
from numasec.__main__ import main
sys.exit(main())
' "$@"
