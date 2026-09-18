# ---------------------------------------------------------------------------
# File: deploy/aws/cert-init/Dockerfile
#
# THE PUBLIC CERTIFICATE, PUT WHERE THE NODE CAN SERVE IT (2026-09-17).
#
# `test-idp.iyasec.io` is an ACM certificate, and until now the LOAD BALANCER
# presented it: the NLB's 443 listener terminated TLS and opened its own
# connection to the node. That cost the thing this service exists to exercise
# — an NLB cannot pass a client certificate through a TLS listener, so
# `GET /tls/sign-in` and RFC 8705 mutual TLS saw none. The load balancer is
# back to TCP passthrough (`environment/nlb.tf`) and the NODE presents the
# public certificate itself, on its own 8081, through `tls.certificateFile`
# and `tls.keyFile` — which the service has always supported and which it
# deliberately leaves alone rather than re-issuing under its own Root
# (`tls/CLAUDE.md`, *The certificate can be one somebody else issued*).
#
# THE ONE THING THAT MAKES THIS A CONTAINER AND NOT A TERRAFORM RESOURCE: the
# private key. ACM releases it only through `ExportCertificate`, only for a
# certificate REQUESTED as exportable, and only encrypted under a passphrase
# the caller supplies. Exporting it in Terraform would write a private key
# into the state file for ever; exporting it here means the key exists in one
# task's ephemeral volume, made again from ACM on every start, and in no
# store, no state and no log. The passphrase is random per run and never
# leaves this container.
#
# An init container in every mock-sts task, `essential: false`, that the node
# waits on with `dependsOn: SUCCESS` — schema-init's shape, and for the same
# reason: a node that cannot get its certificate must not start and serve a
# self-signed one under a public name.
#
# ONLY WHERE `public_hostname` IS SET. `dev` and `ci` request no certificate
# and run no such container; their nodes serve what they always did.
#
# Build from the repository root, beside the other two:
#   docker build -f deploy/aws/cert-init/Dockerfile -t <repo>:cert-<sha> .
# ---------------------------------------------------------------------------
# PINNED TO A VERSION, unlike schema-init's `postgres:18`, because this
# repository has no floating tag to pin to: `aws-cli` publishes exact
# versions and `latest`, and nothing in between.
FROM public.ecr.aws/aws-cli/aws-cli:2.33.0

# `jq` splits the export into its three PEM members and `openssl` takes the
# passphrase back off the key. Both are named rather than assumed present: the
# whole container is four commands, and a missing one of them would fail at
# the first deployment with a message about neither the certificate nor ACM.
RUN dnf install -y jq openssl && dnf clean all && rm -rf /var/cache/dnf

COPY deploy/aws/cert-init/export.sh /usr/local/bin/sts-cert-export
RUN chmod 0755 /usr/local/bin/sts-cert-export

# Not the image's own entrypoint (`aws`): this container runs one script.
ENTRYPOINT ["/usr/local/bin/sts-cert-export"]
