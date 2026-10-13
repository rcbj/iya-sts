# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# iya-sts-companion (#594): the click-through demonstrations, played by a
# separate party in front of the service. companion/CLAUDE.md argues it.
#
# Built from THIS directory (`context: ./companion` in docker-compose.yml),
# so nothing of the service is in it and nothing of it is in the service:
# the service's own Dockerfile removes `companion/` from its copy of the
# tree. Two pinned dependencies, installed from the committed lockfile; the
# optional native build bunyan offers is skipped. The node image the
# service and the test peer are built on.
# ===========================================================================
FROM node:24.16.0-bookworm-slim

WORKDIR /usr/src/companion
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --omit=optional --no-audit --no-fund && \
    npm cache clean --force
COPY *.js ./

# Not root: the companion holds nothing but sessions in memory and reads
# nothing but its environment (and the CA file, when one is mounted).
USER node
ENV COMPANION_PORT=9700
EXPOSE 9700
CMD ["node", "companion.js"]
