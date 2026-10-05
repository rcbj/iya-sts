# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# THE REMOTE XACML POLICY ENFORCEMENT POINT — A RUST BINARY SINCE #444.
#
# **THE BUILD CONTEXT IS THE REPOSITORY ROOT, NOT THIS DIRECTORY**, so this
# image is built from the one copy of the engine in the tree — now the
# `sts-xacml` crate of the Rust workspace in `rust/`, which the runtime uses
# too — and cannot drift from it.
#
#   docker build -f xacml-pep/Dockerfile -t rcbj/xacml-pep .
#
# The Node container this replaces COPIED seven engine modules one by one,
# and `tests/xacml_pep.js` held that list to `engine.js`'s. A Cargo build has
# no such list to keep: the binary links exactly the crates `xacml-pep`
# depends on, and a crate it does not depend on cannot be loaded by it — the
# property the Node shim existed to prove ("the engine is a library with no
# identity service in it") is now the crate graph.
#
# OpenSSL is built from source into the binary (the `openssl` crate's
# `vendored` feature, rust/DESIGN.md D5), so the runtime image needs no libssl
# and serves every certificate the realm's `pep-tls` CA can issue.
# ===========================================================================

FROM rust:1.97-bookworm AS build
WORKDIR /usr/src/rust
COPY rust/ ./
RUN cargo build --release --locked -p xacml-pep

FROM debian:bookworm-slim
# The only package: the system anchors, for a PDP whose certificate a public
# CA issued. PEP_TLS_CA (or PEP_TLS_INSECURE) is what the suite uses.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/pep
COPY --from=build /usr/src/rust/target/release/xacml-pep /usr/local/bin/xacml-pep

# THE VERSION, M.N.O, STAMPED AT BUILD TIME by the binary itself
# (`sts-core::version`, a port of common/version.js): M.N from the one
# VERSION file the service reads too, the build number the UTC build instant
# unless BUILD_NUMBER says otherwise. `version.json` is in the working
# directory, where the binary looks for it and where CI reads it.
COPY VERSION ./VERSION
ARG BUILD_NUMBER=
ARG GIT_COMMIT=
RUN BUILD_NUMBER="${BUILD_NUMBER}" GIT_COMMIT="${GIT_COMMIT}" \
    xacml-pep --stamp . && cat version.json

LABEL org.opencontainers.image.source="https://github.com/rcbj/iya-sts" \
      org.opencontainers.image.title="iya-sts-xacml-pep" \
      org.opencontainers.image.description="IYA STS remote XACML policy enforcement point: pulls policy from the STS and decides locally (port 9090)" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      io.artifacthub.package.readme-url="https://raw.githubusercontent.com/rcbj/iya-sts/main/README.md" \
      io.artifacthub.package.logo-url="https://raw.githubusercontent.com/rcbj/iya-sts/main/docs/logo.png" \
      io.artifacthub.package.license="BUSL-1.1" \
      io.artifacthub.package.keywords="xacml,pep,authorization,policy,iya-sts"

EXPOSE 9090
EXPOSE 9443

# LIVENESS ONLY, never whether the policy is current: a PEP holding a stale
# copy is working, and failing on staleness would turn a PDP outage into a
# restart loop. The binary asks its own /healthcheck — there is no node or
# curl in this image.
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=10s \
  CMD ["xacml-pep", "--healthcheck"]

CMD ["xacml-pep"]
