# ---------------------------------------------------------------------------
# File: deploy/aws/schema-init/Dockerfile
#
# THE SCHEMA, APPLIED TO RDS BEFORE A NODE STARTS (issue #51).
#
# `postgres/schema.sql` is psql, not SQL a driver can run: it uses `\if`,
# `\set`, `\gexec` and `:'variable'` substitution. The compose stack runs it
# inside the database container on the start that creates the cluster
# (`postgres/apply-schema.sh`); RDS has no such hook and no shell, so it runs
# here — an init container in every mock-sts task, `essential: false`, that
# the node waits on with `dependsOn: SUCCESS`. The file is idempotent, so the
# second and third node applying it again changes nothing, and the task
# definition orders node-a ahead of the other two so the first application is
# never concurrent.
#
# It is the ONE place the RDS master credentials are used. The service itself
# dials as the least-privilege role this script creates.
#
# Build from the repository root, so `postgres/schema.sql` is in the context:
#   docker build -f deploy/aws/schema-init/Dockerfile -t <repo>:schema-<sha> .
# ---------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/postgres:18

# The RDS certificate bundle, so psql VERIFIES the server it hands the master
# password to (`PGSSLMODE=verify-full` in the task definition). Fetched at
# build time for the reason the service image fetches its copy.
ARG DATABASE_CA_URL=https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
ADD ${DATABASE_CA_URL} /usr/local/share/sts/database-ca.pem

COPY postgres/schema.sql /usr/local/share/sts/schema.sql
COPY deploy/aws/schema-init/apply.sh /usr/local/bin/sts-schema-apply
RUN chmod 0644 /usr/local/share/sts/database-ca.pem /usr/local/share/sts/schema.sql \
    && chmod 0755 /usr/local/bin/sts-schema-apply

# Not the postgres image's entrypoint: this container never runs a server.
ENTRYPOINT ["/usr/local/bin/sts-schema-apply"]
