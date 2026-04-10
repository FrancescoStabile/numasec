#!/usr/bin/env bash
set -euo pipefail

# numasec v5.0.0 — local install from source
# Installs dependencies, builds the binary, and symlinks to ~/.local/bin/numasec

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; exit 1; }

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$REPO_ROOT/agent"
INSTALL_DIR="${NUMASEC_INSTALL_DIR:-$HOME/.local/bin}"

# --- checks ---
command -v bun >/dev/null 2>&1 || fail "bun is required. Install: curl -fsSL https://bun.sh/install | bash"

BUN_VERSION=$(bun --version)
info "bun $BUN_VERSION detected"

if [[ ! -d "$AGENT_DIR" ]]; then
  fail "agent/ directory not found at $AGENT_DIR"
fi

# --- install deps ---
info "Installing dependencies..."
cd "$AGENT_DIR"
bun install --frozen-lockfile 2>/dev/null || bun install
ok "Dependencies installed"

# --- build ---
info "Building numasec binary..."
bun run build
ok "Build complete"

# --- find the binary for this platform ---
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="x64" ;;
  aarch64) ARCH="arm64" ;;
esac

DIST_NAME="numasec-${PLATFORM}-${ARCH}"
BINARY="$AGENT_DIR/packages/numasec/dist/${DIST_NAME}/bin/numasec"

if [[ ! -f "$BINARY" ]]; then
  # try baseline variant
  BINARY="$AGENT_DIR/packages/numasec/dist/${DIST_NAME}-baseline/bin/numasec"
fi

if [[ ! -f "$BINARY" ]]; then
  echo ""
  info "Available builds:"
  ls -d "$AGENT_DIR/packages/numasec/dist"/*/bin/numasec 2>/dev/null || echo "  (none found)"
  fail "No binary found for ${PLATFORM}-${ARCH}"
fi

ok "Binary: $BINARY"

# --- symlink ---
mkdir -p "$INSTALL_DIR"
ln -sf "$BINARY" "$INSTALL_DIR/numasec"
ok "Symlinked to $INSTALL_DIR/numasec"

# --- verify ---
if command -v numasec >/dev/null 2>&1; then
  VERSION=$(numasec --version 2>/dev/null || echo "unknown")
  echo ""
  echo -e "${BOLD}${GREEN}numasec $VERSION installed successfully${NC}"
  echo -e "  Run: ${CYAN}numasec${NC}"
else
  echo ""
  ok "Installed to $INSTALL_DIR/numasec"
  echo -e "  Add to PATH: ${CYAN}export PATH=\"$INSTALL_DIR:\$PATH\"${NC}"
fi
