# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# THE ONE CONTAINER THE schema-validation MODE RUNS IN (#1353). The tests image
# brings the compiled service, the jobs, Chrome and Selenium; this adds what the
# compose stacks run as containers of their own. tests/schema-validation/run.sh
# builds both.
ARG STS_SCHEMA_BASE=iya-sts-schema-base:local
FROM ${STS_SCHEMA_BASE}

# One RUN, for the reason tests/Dockerfile gives: a stale `apt-get update` layer.
RUN apt-get update \
  && apt-get install -y --no-install-recommends postgresql postgresql-contrib \
       mariadb-server mariadb-client haproxy iproute2 util-linux openssl \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /openbao/file /openbao/client /openbao/startup /run/secrets \
  && ln -s /openbao/client /run/secrets/openbao \
  && ln -s /openbao/startup /run/secrets/openbao-startup

COPY --from=openbao/openbao:latest /usr/bin/bao /usr/local/bin/bao

# Deliberately not dependencies of the service (common/secrets.js,
# persistence/sql_dialect.js), and optional peers, so `npm install` inside this
# tree does nothing and says "up to date". The service image's arrangement: a
# prefix of their own outside the tree, and NODE_PATH.
RUN mkdir -p /opt/sts-sdks && cd /opt/sts-sdks \
  && npm init -y > /dev/null \
  && npm install --omit=dev node-vault mysql2 \
  && npm cache clean --force
ENV NODE_PATH=/opt/sts-sdks/node_modules:${NODE_PATH}

CMD [ "./tests/schema-validation/in-container.sh" ]
