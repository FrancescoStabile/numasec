FROM debian:bookworm-slim AS base

ARG BUN_RUNTIME_TRANSPILER_CACHE_PATH=0
ENV BUN_RUNTIME_TRANSPILER_CACHE_PATH=${BUN_RUNTIME_TRANSPILER_CACHE_PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates ripgrep curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS build-amd64
COPY agent/packages/numasec/dist/numasec-linux-x64-baseline/bin/numasec /usr/local/bin/numasec

FROM base AS build-arm64
COPY agent/packages/numasec/dist/numasec-linux-arm64/bin/numasec /usr/local/bin/numasec

ARG TARGETARCH
FROM build-${TARGETARCH}
RUN numasec --version
ENTRYPOINT ["numasec"]
