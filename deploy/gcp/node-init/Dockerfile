# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# File: deploy/gcp/node-init/Dockerfile
#
# WHAT A GCP NODE RUNS BEFORE mock-sts STARTS (issue #95): two commands, one
# image, the parts of an ECS task definition a VM has to do for itself.
#
#   sts-secrets   Secret Manager → a KEY=VALUE env file on the VM's tmpfs,
#                 which the next container takes as --env-file (ECS's
#                 `secrets` injection)
#   sts-cert      the public certificate and its key, from the foundation's
#                 secret — issued or renewed through ACME first, on node-a,
#                 when it must be (AWS's cert-init, which exported ACM's)
#
# NO GCLOUD: both talk to Secret Manager's REST API with the VM's own token
# from the metadata server, which keeps the image small and its only
# credential the one the VM already has. lego (MIT) is the ACME client; its
# `gcloud` DNS provider writes the DNS-01 record with the same credentials.
#
# Build from the repository root:
#   docker build -f deploy/gcp/node-init/Dockerfile -t <registry>/mock-sts:init-<sha> .
# ---------------------------------------------------------------------------
# Google's mirror of Docker Hub, as the schema image: no Docker Hub pull limit.
FROM mirror.gcr.io/library/debian:bookworm-slim

# `curl` and `jq` for the REST calls, `openssl` to read a certificate's
# names and expiry, `ca-certificates` to trust Google and the ACME server.
RUN apt-get update \
    && apt-get -y install --no-install-recommends ca-certificates curl jq openssl \
    && rm -rf /var/lib/apt/lists/*

# PINNED, AND CHECKED against the release's own checksum file.
ARG LEGO_VERSION=4.25.2
RUN set -eu; \
    base="https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}"; \
    tarball="lego_v${LEGO_VERSION}_linux_amd64.tar.gz"; \
    cd /tmp; \
    curl -fsSL --retry 5 -o "${tarball}" "${base}/${tarball}"; \
    curl -fsSL --retry 5 -o sums.txt "${base}/lego_${LEGO_VERSION}_checksums.txt"; \
    grep " ${tarball}\$" sums.txt | sha256sum -c -; \
    tar -xzf "${tarball}" -C /usr/local/bin lego; \
    rm -f "${tarball}" sums.txt; \
    lego --version

COPY deploy/gcp/node-init/secrets.sh /usr/local/bin/sts-secrets
COPY deploy/gcp/node-init/cert.sh /usr/local/bin/sts-cert
COPY deploy/gcp/node-init/lib.sh /usr/local/lib/sts/lib.sh
RUN chmod 0755 /usr/local/bin/sts-secrets /usr/local/bin/sts-cert \
    && chmod 0644 /usr/local/lib/sts/lib.sh

# No entrypoint of its own: the unit names the command (sts-secrets or sts-cert).
