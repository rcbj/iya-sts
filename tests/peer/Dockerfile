# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# sts-test-peer (#586): the far party the protocol jobs talk to — a SAML 2.0
# service provider, a SAML 1.1 and a WS-Federation relying party, an RFC 9470
# and a GNAP resource server, and an SSF receiver — on one port, with a JSON
# readback. tests/CLAUDE.md, *THE TEST PEER*, argues it.
#
# The node image the service and the tests image are built on, from the
# ghcr.io mirror (x-mirror-contexts in docker-compose-run-tests.yml;
# .github/image-mirror.txt). Four pinned dependencies, installed from the
# committed lockfile; the optional native build bunyan offers is skipped.
#
# NOTHING HERE IS A KEY: the peer makes its CA, its TLS certificate and every
# tenant's keys when it starts and when a job configures a tenant. It writes
# the CA CERTIFICATE, and only that, to the shared directory it is given
# (TEST_PEER_CA_DIR).
# ===========================================================================
FROM node:24.16.0-bookworm-slim

WORKDIR /usr/src/peer
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --omit=optional --no-audit --no-fund && \
    npm cache clean --force
COPY *.js ./

# ROOT, ON PURPOSE, for mailpit-tls's reason (docker-compose-run-tests.yml):
# the shared directory is a named volume several containers mount, whichever
# of them creates it owns its root, and the peer has to make its own
# subdirectory there and write the CA certificate other containers' users
# read. The peer listens on an unpublished port of a private bridge and
# holds nothing but keys it made for this run.
ENV TEST_PEER_PORT=9600
EXPOSE 9600
CMD ["node", "peer.js"]
