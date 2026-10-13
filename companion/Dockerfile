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
# tree. Three pinned dependencies, installed from the committed lockfile;
# the optional native build bunyan offers is skipped. The node image the
# service and the test peer are built on.
#
# TWO STAGES SINCE #595. The Kerberos demonstration's acceptor is MIT
# Kerberos's GSS-API through the `kerberos` package, a native module: it is
# BUILT FROM SOURCE here (`npm_config_build_from_source`, so its install
# script compiles with node-gyp rather than downloading a prebuilt binary
# from GitHub), against Debian's MIT headers, and the final image carries
# the runtime libraries only — no compiler.
# ===========================================================================
FROM node:24.16.0-bookworm-slim AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 make g++ \
      libkrb5-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/companion
COPY package.json package-lock.json ./
RUN npm_config_build_from_source=true \
    npm ci --omit=dev --omit=optional --no-audit --no-fund && \
    npm cache clean --force

FROM node:24.16.0-bookworm-slim

# The MIT Kerberos runtime the acceptor loads (libgssapi_krb5.so.2, with
# libkrb5 and libcom_err). No krb5.conf: an acceptor holding a keytab asks
# no KDC.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libgssapi-krb5-2 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/companion
COPY --from=build /usr/src/companion/node_modules ./node_modules
COPY package.json package-lock.json *.js ./

# Not root: the companion holds nothing but sessions in memory and its
# keytab in a temporary file only it can read, and reads nothing but its
# environment (and the CA file, when one is mounted).
USER node
ENV COMPANION_PORT=9700
EXPOSE 9700 8888
CMD ["node", "companion.js"]
