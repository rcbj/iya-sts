# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# File: deploy/gcp/schema-init/Dockerfile
#
# THE SCHEMA, APPLIED TO CLOUD SQL BEFORE A NODE STARTS (issue #95) — the
# AWS image's script and schema, without the RDS certificate bundle.
#
# THE SAME SCRIPT AS AWS (deploy/aws/schema-init/apply.sh), not a copy: one
# place says how the master credentials are used. What differs is only the
# trust anchor. RDS's is a public bundle fetched at build time; a Cloud SQL
# instance's CA arrives with the instance, so the node's sts-schema unit
# MOUNTS it at the path the script reads (/usr/local/share/sts/
# database-ca.pem) and one image serves every environment.
#
# Build from the repository root:
#   docker build -f deploy/gcp/schema-init/Dockerfile -t <registry>/mock-sts:schema-<sha> .
# ---------------------------------------------------------------------------
FROM mirror.gcr.io/library/postgres:18

COPY postgres/schema.sql /usr/local/share/sts/schema.sql
COPY deploy/aws/schema-init/apply.sh /usr/local/bin/sts-schema-apply
RUN chmod 0644 /usr/local/share/sts/schema.sql \
    && chmod 0755 /usr/local/bin/sts-schema-apply

# Not the postgres image's entrypoint: this container never runs a server.
ENTRYPOINT ["/usr/local/bin/sts-schema-apply"]
