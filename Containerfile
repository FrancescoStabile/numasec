# ══════════════════════════════════════════════════════════════════════════════
# NumaSec v3 - Container
# AI Pentester with SOTA Prompt Engineering
# ══════════════════════════════════════════════════════════════════════════════
# Build:  podman build -t numasec .
# Run:    podman run -it --network host -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" numasec

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

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
# Stage 2: ProjectDiscovery Tools (nuclei, httpx, subfinder)
# ══════════════════════════════════════════════════════════════════════════════

# nuclei
RUN NUCLEI_VERSION=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /tmp && \
    mv /tmp/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f /tmp/nuclei.zip

# httpx
RUN HTTPX_VERSION=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    curl -sL "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /tmp && \
    mv /tmp/httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm -f /tmp/httpx.zip

# subfinder
RUN SUBFINDER_VERSION=$(curl -sL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    curl -sL "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /tmp && \
    mv /tmp/subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm -f /tmp/subfinder.zip

# ffuf (web fuzzer)
RUN FFUF_VERSION=$(curl -sL https://api.github.com/repos/ffuf/ffuf/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    curl -sL "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp && \
    mv /tmp/ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && \
    rm -f /tmp/ffuf.tar.gz

# Update nuclei templates
RUN nuclei -ut || true

# ══════════════════════════════════════════════════════════════════════════════
# Stage 3: NumaSec Installation
# ══════════════════════════════════════════════════════════════════════════════

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install NumaSec and dependencies
RUN pip install --no-cache-dir .

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

# Run NumaSec
if [ $# -eq 0 ]; then
    exec python -m numasec
fi

exec python -m numasec "$@"
EOF

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
