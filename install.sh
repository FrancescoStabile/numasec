#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${CYAN}▸${NC} $*"; }
ok() { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; exit 1; }

usage() {
  cat <<EOF
Usage: bash install.sh [options]

Options:
  --validate             Run typecheck + targeted validation tests before install
  --install-dir <path>   Installation dir (default: \$HOME/.bun/bin if present, else \$HOME/.local/bin)
  -h, --help             Show this help

Examples:
  bash install.sh
  bash install.sh --validate
  bash install.sh --install-dir /usr/local/bin
EOF
}

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$REPO_ROOT/agent"
PKG_DIR="$AGENT_DIR/packages/numasec"
DEFAULT_INSTALL_DIR="$HOME/.local/bin"
if [[ -d "$HOME/.bun/bin" ]]; then
  DEFAULT_INSTALL_DIR="$HOME/.bun/bin"
fi
INSTALL_DIR="${NUMASEC_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
RUN_VALIDATE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
  --validate)
    RUN_VALIDATE=1
    shift
    ;;
  --install-dir)
    [[ $# -ge 2 ]] || fail "--install-dir requires a value"
    INSTALL_DIR="$2"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    fail "Unknown option: $1"
    ;;
  esac
done

command -v bun >/dev/null 2>&1 || fail "bun is required. Install via https://bun.sh"
[[ -d "$AGENT_DIR" ]] || fail "agent/ directory not found at $AGENT_DIR"

PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
x86_64) ARCH="x64" ;;
aarch64) ARCH="arm64" ;;
esac

supports_avx2() {
  [[ "$ARCH" == "x64" ]] || return 1
  if [[ "$PLATFORM" == "linux" ]]; then
    grep -qiE '(^|[[:space:]])avx2([[:space:]]|$)' /proc/cpuinfo 2>/dev/null
    return $?
  fi
  if [[ "$PLATFORM" == "darwin" ]]; then
    [[ "$(sysctl -n hw.optional.avx2_0 2>/dev/null || echo 0)" == "1" ]]
    return $?
  fi
  return 1
}

uses_musl() {
  [[ "$PLATFORM" == "linux" ]] || return 1
  [[ -f /etc/alpine-release ]] && return 0
  ldd --version 2>&1 | grep -qi "musl"
}

info "Installing dependencies..."
cd "$AGENT_DIR"
bun install --frozen-lockfile || bun install
ok "Dependencies installed"

if [[ "$RUN_VALIDATE" -eq 1 ]]; then
  info "Running typecheck..."
  bun run typecheck
  ok "Typecheck passed"

  info "Running targeted validation tests..."
  cd "$PKG_DIR"
  bun test --timeout 30000 \
    test/security/primitive-tools.test.ts \
    test/security/legacy-wrappers.test.ts \
    test/security/planner-policy.test.ts \
    test/security/plan-next.test.ts \
    test/security/report-projection.test.ts \
    test/server/security-read-model.test.ts \
    test/command/taxonomy.test.ts \
    test/command/resolve.test.ts \
    test/permission/approval.test.ts \
    test/cli/tui/security-view-model.test.ts \
    test/cli/tui/sync-pagination.test.ts
  ok "Targeted validation tests passed"
fi

info "Building numasec binary..."
cd "$PKG_DIR"
BUILD_ARGS=(--single)
if uses_musl; then
  BUILD_ARGS=(--musl-only)
fi
if [[ "$ARCH" == "x64" ]] && ! supports_avx2 && ! uses_musl; then
  BUILD_ARGS+=(--baseline)
fi
info "Build flags: ${BUILD_ARGS[*]}"
NUMASEC_CHANNEL=local NUMASEC_VERSION=local bun run build "${BUILD_ARGS[@]}"
ok "Build complete"

DIST_NAME="numasec-${PLATFORM}-${ARCH}"
if uses_musl; then
  DIST_NAME="${DIST_NAME}-musl"
fi
BINARY="$PKG_DIR/dist/${DIST_NAME}/bin/numasec"
if [[ ! -f "$BINARY" ]] && [[ "$ARCH" == "x64" ]] && ! supports_avx2; then
  BINARY="$PKG_DIR/dist/${DIST_NAME}-baseline/bin/numasec"
fi

if [[ ! -f "$BINARY" ]] && uses_musl && [[ "$ARCH" == "x64" ]] && ! supports_avx2; then
  BINARY="$PKG_DIR/dist/numasec-${PLATFORM}-${ARCH}-baseline-musl/bin/numasec"
fi

if [[ ! -f "$BINARY" ]]; then
  echo ""
  info "Available builds:"
  ls -d "$PKG_DIR/dist"/*/bin/numasec 2>/dev/null || echo "  (none found)"
  fail "No built binary found for ${PLATFORM}-${ARCH}"
fi

ok "Built binary: $BINARY"

mkdir -p "$INSTALL_DIR"
ln -sf "$BINARY" "$INSTALL_DIR/numasec"
ok "Installed: $INSTALL_DIR/numasec"

info "Running smoke checks..."
VERSION="$("$INSTALL_DIR/numasec" --version 2>/dev/null || true)"
[[ -n "$VERSION" ]] || fail "Smoke check failed: --version returned empty output"
ok "Version: $VERSION"

HELP_LINE="$("$INSTALL_DIR/numasec" --help 2>/dev/null | head -n 1 || true)"
if [[ -n "$HELP_LINE" ]]; then
  ok "Help check passed"
else
  warn "Help output not available (continuing)"
fi

RESOLVED_NUMASEC="$(command -v numasec 2>/dev/null || true)"

echo ""
echo -e "${BOLD}${GREEN}numasec installed successfully${NC}"
echo -e "Run with: ${CYAN}$INSTALL_DIR/numasec${NC}"

if [[ -z "$RESOLVED_NUMASEC" ]]; then
  echo -e "Add to PATH: ${CYAN}export PATH=\"$INSTALL_DIR:\$PATH\"${NC}"
  exit 0
fi

if [[ "$RESOLVED_NUMASEC" == "$INSTALL_DIR/numasec" ]]; then
  ok "Default numasec command points to this install"
  echo -e "If your current shell still executes an old cached path, run: ${CYAN}hash -r${NC}"
  exit 0
fi

echo ""
warn "numasec currently resolves to: $RESOLVED_NUMASEC"
warn "Your PATH is picking another installation first."
echo -e "Put ${CYAN}$INSTALL_DIR${NC} before other entries in PATH, for example:"
echo -e "  ${CYAN}export PATH=\"$INSTALL_DIR:\$PATH\"${NC}"
echo -e "If your current shell still executes an old cached path, run: ${CYAN}hash -r${NC}"
