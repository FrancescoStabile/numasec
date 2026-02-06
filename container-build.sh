#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NumaSec Container Build Script
# ══════════════════════════════════════════════════════════════════════════════

set -e

CONTAINER_TOOL="${CONTAINER_TOOL:-podman}"
IMAGE_NAME="numasec:latest"

echo "🐳 Building NumaSec container with $CONTAINER_TOOL..."
echo ""

$CONTAINER_TOOL build -t "$IMAGE_NAME" .

echo ""
echo "✅ Build complete!"
echo ""
echo "Image: $IMAGE_NAME"
echo ""
echo "Tools installed:"
echo "  • nmap         (port scanning)"
echo "  • sqlmap       (SQLi exploitation)"
echo "  • nuclei       (CVE scanning)"
echo "  • httpx        (HTTP probing)"
echo "  • subfinder    (subdomain enum)"
echo "  • playwright   (browser automation)"
echo ""
echo "Run with:"
echo "  ./container-run.sh"
echo ""
