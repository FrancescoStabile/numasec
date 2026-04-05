FROM alpine AS base

# Disable the runtime transpiler cache by default inside Docker containers.
# On ephemeral containers, the cache is not useful
ARG BUN_RUNTIME_TRANSPILER_CACHE_PATH=0
ENV BUN_RUNTIME_TRANSPILER_CACHE_PATH=${BUN_RUNTIME_TRANSPILER_CACHE_PATH}

RUN apk add --no-cache \
    libgcc libstdc++ ripgrep \
    python3 py3-pip py3-cryptography

# Install numasec Python package (MCP security scanner backend)
COPY pyproject.toml README.md /tmp/numasec/
COPY numasec/ /tmp/numasec/numasec/
RUN pip install --no-cache-dir --break-system-packages "/tmp/numasec[mcp]" \
    && rm -rf /tmp/numasec

# TUI binary connects to Python MCP server via this env var
ENV NUMASEC_PYTHON_PATH=/usr/bin/python3

FROM base AS build-amd64
COPY agent/packages/numasec/dist/numasec-linux-x64-baseline-musl/bin/numasec /usr/local/bin/numasec

FROM base AS build-arm64
COPY agent/packages/numasec/dist/numasec-linux-arm64-musl/bin/numasec /usr/local/bin/numasec

ARG TARGETARCH
FROM build-${TARGETARCH}
RUN numasec --version
ENTRYPOINT ["numasec"]
