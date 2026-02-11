# ══════════════════════════════════════════════════════════════════════════════
# NumaSec v3 - Container
# AI Pentester with SOTA Prompt Engineering
# ══════════════════════════════════════════════════════════════════════════════
# Build:  podman build -t numasec .
# Run:    podman run -it --network host -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" numasec

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TERM=xterm-256color \
    COLORTERM=truecolor

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: System Dependencies + Security Tools
# ══════════════════════════════════════════════════════════════════════════════

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    curl \
    wget \
    git \
    unzip \
    ca-certificates \
    # Network utilities
    iputils-ping \
    dnsutils \
    netcat-openbsd \
    # Security tools
    nmap \
    dirb \
    # Playwright dependencies
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# sqlmap (clone latest from GitHub)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: ProjectDiscovery Tools (nuclei, httpx, subfinder) + ffuf
# Pinned versions for reproducible builds. Update periodically.
# ══════════════════════════════════════════════════════════════════════════════

ARG NUCLEI_VERSION=3.7.0
ARG HTTPX_VERSION=1.8.1
ARG SUBFINDER_VERSION=2.12.0
ARG FFUF_VERSION=2.1.0

# Install all security tools in a single layer (fewer layers = smaller image)
RUN set -eux && \
    # --- nuclei ---
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei_extract && \
    mv /tmp/nuclei_extract/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    # --- httpx ---
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /tmp/httpx_extract && \
    mv /tmp/httpx_extract/httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    # --- subfinder ---
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /tmp/subfinder_extract && \
    mv /tmp/subfinder_extract/subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    # --- ffuf ---
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp && \
    mv /tmp/ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && \
    # --- cleanup ---
    rm -rf /tmp/*.zip /tmp/*.tar.gz /tmp/*_extract /tmp/LICENSE* /tmp/README*

# Update nuclei templates
RUN nuclei -ut || true

# ══════════════════════════════════════════════════════════════════════════════
# Stage 3: NumaSec Installation
# ══════════════════════════════════════════════════════════════════════════════

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install NumaSec with all optional dependencies
# - [mcp]: MCP server support (Claude Desktop, Cursor, VS Code)
# - [pdf]: Professional PDF report generation
RUN pip install --no-cache-dir '.[mcp,pdf]'

# Install Playwright browser
RUN playwright install chromium

# ══════════════════════════════════════════════════════════════════════════════
# Stage 4: Configuration
# ══════════════════════════════════════════════════════════════════════════════

# Create data directory
RUN mkdir -p /root/.numasec/sessions

# Entrypoint
COPY <<'EOF' /entrypoint.sh
#!/bin/bash
set -e

# If no args, run NumaSec interactively
if [ $# -eq 0 ]; then
    exec python -m numasec
fi

# If the first arg is an executable (python, bash, sh, etc.),
# run it directly instead of passing to numasec
if command -v "$1" >/dev/null 2>&1; then
    exec "$@"
fi

# Otherwise, pass args to numasec (e.g. "check", "--demo")
exec python -m numasec "$@"
EOF

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
