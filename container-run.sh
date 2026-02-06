#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# NumaSec Container Run Script
# ══════════════════════════════════════════════════════════════════════════════

set -e

CONTAINER_TOOL="${CONTAINER_TOOL:-podman}"
IMAGE_NAME="numasec:latest"

# Ensure ~/.numasec directory exists
mkdir -p "$HOME/.numasec/sessions" "$HOME/.numasec/logs"

# Load .env if exists (project-local API keys)
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

# Check if API keys are available
if [ -z "$DEEPSEEK_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ No API keys found!"
    echo ""
    echo "Create .env file with:"
    echo "  DEEPSEEK_API_KEY=sk-your-key-here"
    echo ""
    echo "Or set environment variable:"
    echo "  export DEEPSEEK_API_KEY=\"sk-...\""
    echo ""
    exit 1
fi

echo "🚀 Starting NumaSec container..."
echo ""
echo "Tools available:"
echo "  ✓ nmap, sqlmap, nuclei, httpx, subfinder"
echo "  ✓ Playwright browser (Chromium)"
echo ""
echo "Sessions saved: ~/.numasec/sessions/"
echo ""

# Run container with environment variables
$CONTAINER_TOOL run -it --rm \
    --network host \
    -e DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY}" \
    -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
    -e OPENAI_API_KEY="${OPENAI_API_KEY}" \
    -v "$HOME/.numasec:/root/.numasec:z" \
    "$IMAGE_NAME" "$@"
