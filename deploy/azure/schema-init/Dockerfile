# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# File: deploy/azure/schema-init/Dockerfile
#
# THE SCHEMA, APPLIED TO A FLEXIBLE SERVER BEFORE A NODE STARTS (issue #96) —
# AWS's script and schema, with Azure's two roots.
#
# THE SAME SCRIPT AS AWS AND GCP (deploy/aws/schema-init/apply.sh), not a
# copy: one place says how the administrator's credentials are used. What
# differs is only the trust anchor, which the script reads at
# /usr/local/share/sts/database-ca.pem: a Flexible Server's certificate
# chains to DigiCert Global Root G2 or, after Azure's rotation, to Microsoft
# RSA Root Certificate Authority 2017. Both are PUBLIC roots, so they are
# taken from Debian's ca-certificates by name — the two and no others, so
# the one connection that carries the administrator's password trusts
# exactly what Azure says it uses — and the server is verified by name
# (`verify-full`).
#
# Build from the repository root:
#   docker build -f deploy/azure/schema-init/Dockerfile -t <registry>/mock-sts:schema-<sha> .
# ---------------------------------------------------------------------------
FROM mirror.gcr.io/library/postgres:18

RUN apt-get update \
    && apt-get -y install --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/share/sts \
    && cat /usr/share/ca-certificates/mozilla/DigiCert_Global_Root_G2.crt \
           /usr/share/ca-certificates/mozilla/Microsoft_RSA_Root_Certificate_Authority_2017.crt \
         > /usr/local/share/sts/database-ca.pem \
    && chmod 0644 /usr/local/share/sts/database-ca.pem

COPY postgres/schema.sql /usr/local/share/sts/schema.sql
COPY deploy/aws/schema-init/apply.sh /usr/local/bin/sts-schema-apply
RUN chmod 0644 /usr/local/share/sts/schema.sql \
    && chmod 0755 /usr/local/bin/sts-schema-apply

# Not the postgres image's entrypoint: this container never runs a server.
ENTRYPOINT ["/usr/local/bin/sts-schema-apply"]
