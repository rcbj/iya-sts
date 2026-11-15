# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: rust/Dockerfile
#
# ---------------------------------------------------------------------------
# THE RUST RUNTIME'S IMAGE (#444, phase 3). Built from the REPOSITORY ROOT:
#
#   docker build -f rust/Dockerfile -t iya-sts-rust .
#
# WHY A FILE OF ITS OWN RATHER THAN STAGES IN THE ROOT Dockerfile. The brief
# for this phase is that the Node image and its build do not change, and a
# stage added to the root file changes its build even when nothing names
# it: the legacy builder builds every stage, a stage added at the end
# becomes the default target, and the root file's cache keys move with its
# text. A second file beside the code it builds, as `xacml-pep/Dockerfile`
# is for the remote PEP, leaves the Node build byte for byte as it is. The
# cost is that the TypeScript stage below repeats the root file's: the same
# base, the same two installs and `build-typescript.sh --strip`. It has to
# be kept in step until phase 10 makes this the only image (rust/DESIGN.md
# section 3.2), and `build-typescript.sh` is the one place either of them
# says how the bundles are made.
#
# THE BASE IS THE NODE IMAGE'S, debian:bookworm-slim (7257fdbff), with the
# packages operators' scripts and the deployments run inside the container:
# iproute2 (`ip addr add` for the per-realm SPIFFE addresses, in the
# compose files' `command`), curl and jq with ca-certificates (bf81b99df,
# rcbj 2026-11-14: operators' utility scripts). The same user (10001), the
# same working directory, the same `data/` owned by it, the same
# `CONFIG_FILE` and the same EXPOSE list, so a volume, a seeder or a
# compose file written for the Node image finds what it expects.
#
# WHAT THE NODE IMAGE HAS THAT THIS ONE DOES NOT, and why:
#   * `node` itself (`/usr/local/bin/node`): nothing here runs it. The
#     compose files' healthcheck is `node -e`, so it changes in phase 10
#     with them (the runtime grows a `--healthcheck`, as the PEP has);
#   * the service's JavaScript tree, `node_modules`, `/opt/sts-sdk` and
#     `NODE_PATH`, `NODE_ENV`, and both SBOMs (`sbom.cdx.json`,
#     `sbom-sdks.cdx.json`, npm's): a Cargo SBOM is phase 10's;
#   * the embedded debugger's tree (`debugger/embedded/`): its listener is
#     not ported (phase 9);
#   * `os-packages.txt` is written, as the Node image writes it.
# ---------------------------------------------------------------------------

# The static surfaces' bundles, made exactly as the root Dockerfile's
# `typescript` stage makes them (no native module: nothing here loads it).
FROM node:24.22.1-bookworm-slim AS typescript
WORKDIR /usr/src/sts
COPY package*.json .npmrc ./
COPY node-ldapjs ./node-ldapjs
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY tests/package*.json ./tests/
RUN npm ci --prefix ./tests && npm cache clean --force
COPY . ./
RUN STS_IN_IMAGE_BUILD=1 ./build-typescript.sh --strip
# What the runtime serves, at the paths the Node image has them under
# /usr/src/sts (sts-http's `WebRoot`, `STS_WEB_ROOT`): every file the build
# packed — each surface's runtime and the map data, found by the `.br`
# beside it — with its `.br` and `.gz`, the catalogs the browser
# translates from (/web/locales), the server prose `/admin-api` translates
# by `Accept-Language` (#543, common/prose_locales), the favicon, and
# version.json, stamped
# here as the Node image stamps it (`common/version.js --stamp`).
ARG GIT_COMMIT=
ARG STS_RELEASE=
ARG BUILD_NUMBER=
ARG STS_VERSION_RELEASE=
RUN GIT_COMMIT="${GIT_COMMIT}" STS_RELEASE="${STS_RELEASE}" \
    BUILD_NUMBER="${BUILD_NUMBER}" \
    STS_VERSION_RELEASE="${STS_VERSION_RELEASE}" \
    node common/version.js --stamp . \
 && mkdir -p /out \
 && find . -path ./node_modules -prune -o -path ./tests -prune -o \
      -name '*.br' -print | while read -r br; do \
      f="${br%.br}"; \
      for one in "$f" "$f.br" "$f.gz"; do \
        mkdir -p "/out/$(dirname "$one")" && cp "$one" "/out/$one"; \
      done; \
    done \
 && for f in admin-ui/console.js portal/portal-spa.js home/home-spa.js \
             authn/authn-spa.js common/favicon.ico version.json; do \
      test -s "/out/$f" || { test -s "$f" && cp "$f" "/out/$f"; } \
        || { echo "rust/Dockerfile: no $f" >&2; exit 1; }; \
    done \
 && cp -r common/locales /out/common/locales \
 && cp -r common/prose_locales /out/common/prose_locales

FROM rust:1.97-bookworm AS build
WORKDIR /usr/src/rust
# How many compiler jobs the build may run (`docker build --build-arg
# CARGO_BUILD_JOBS=2` on a machine shared with other work); empty is
# cargo's own default, one per CPU.
ARG CARGO_BUILD_JOBS=
# Serialised behind the TypeScript stage, so the two heavy stages never run
# at once: BuildKit builds independent stages in parallel.
COPY --from=typescript /out/common/favicon.ico /tmp/after-typescript
COPY rust/ ./
RUN if [ -n "${CARGO_BUILD_JOBS}" ]; then export CARGO_BUILD_JOBS; \
    else unset CARGO_BUILD_JOBS; fi \
 && cargo build --release --locked -p sts-runtime

FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        iproute2 \
        curl \
        jq \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/sts
COPY --from=build /usr/src/rust/target/release/sts-runtime \
     /usr/local/bin/sts-runtime
COPY --from=typescript /out/ ./
COPY env ./env
COPY VERSION ./VERSION
# Where the static surfaces' built files are (sts-http's WebRoot).
ENV STS_WEB_ROOT=/usr/src/sts
RUN dpkg-query -W -f='${Package} ${Version}\n' > /usr/src/sts/os-packages.txt
ARG GIT_COMMIT=
LABEL org.opencontainers.image.source="https://github.com/rcbj/iya-sts" \
      org.opencontainers.image.title="iya-sts-rust" \
      org.opencontainers.image.description="IYA STS, the Rust runtime (#444): not yet a replacement for the Node image" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.revision="${GIT_COMMIT}"
ENV CONFIG_FILE=./env/local.js
EXPOSE 8081
EXPOSE 8082
EXPOSE 88/tcp
EXPOSE 88/udp
EXPOSE 389
EXPOSE 636
EXPOSE 8092
EXPOSE 8181
EXPOSE 8444
EXPOSE 8446
RUN groupadd --system --gid 10001 sts \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
               --home-dir /nonexistent --shell /usr/sbin/nologin sts \
    && mkdir -p /usr/src/sts/data/risk-uploads \
    && chown -R 10001:10001 /usr/src/sts/data
USER 10001:10001
CMD [ "sts-runtime" ]
