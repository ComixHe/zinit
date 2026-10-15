# SPDX-FileCopyrightText: 2026 YuMing He <ComixHe1895@outlook.com>
#
# SPDX-License-Identifier: MIT

# The artifact image: a scratch image whose only content is the static zinit
# binary, meant to be consumed with
#
#   COPY --from=ghcr.io/comixhe/zinit:v0.2.1 /zinit /sbin/zinit
#
# so other images get an init without vendoring the tarball themselves, and
# without needing an emulator for their target architecture.

FROM --platform=$BUILDPLATFORM alpine:3@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS pack
ARG VERSION
ARG TARGETARCH
ARG MODE=ReleaseSmall
RUN --mount=type=bind,source=dist,target=/artifacts,readonly \
   ver="${VERSION#v}" \
   && case "$TARGETARCH" in \
   amd64)   t=x86_64  ;; \
   arm64)   t=aarch64 ;; \
   riscv64) t=riscv64 ;; \
   *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
   esac \
   && case "$MODE" in \
   ReleaseSmall|ReleaseSafe) ;; \
   *) echo "unsupported MODE: $MODE" >&2; exit 1 ;; \
   esac \
   && cd /artifacts \
   && sha256sum -c SHA256SUMS >/dev/null \
   && tar -xzf "zinit-${ver}-${t}-linux-${MODE}.tar.gz" -C /tmp \
   && install -D -m 0755 "/tmp/zinit-${ver}-${t}-linux-${MODE}/zinit" /out/zinit

FROM scratch
ARG VERSION
LABEL org.opencontainers.image.title="zinit" \
   org.opencontainers.image.description="A tiny, libc-less init for Linux containers" \
   org.opencontainers.image.source="https://github.com/ComixHe/zinit" \
   org.opencontainers.image.licenses="MIT" \
   org.opencontainers.image.version="${VERSION}"
COPY --link --from=pack /out/zinit /zinit
ENTRYPOINT ["/zinit", "--"]
