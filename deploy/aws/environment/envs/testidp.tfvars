# ---------------------------------------------------------------------------
# `testidp`: a single-region deployment behind a public name, not a test run.
#
# Applied like any environment (entrypoint.sh passes this file when it exists
# for TF_ENV), with IMAGE_TAG and ALLOWED_CIDR as usual:
#   IMAGE_TAG=<tag> deploy/aws/terraform-local.sh testidp apply
#   deploy/aws/terraform-local.sh testidp destroy
# ALLOWED_CIDR is left unset: the launcher admits THIS host's current public
# address and nothing else, looked up on every build.
# Or from GitHub: .github/workflows/testidp-deploy.yml (allowed_ip is a
# required input — a workflow cannot see its dispatcher's address) and
# testidp-destroy.yml.
#
# What makes it different from `dev` and `ci`, and why:
#   * a public name and certificate — test-idp.iyasec.io, an EXPORTABLE ACM
#     certificate (dns.tf) that the NODES present on their own 8081. The load
#     balancer passes TLS through, as it does for dev and ci, so a client
#     certificate still reaches the service; `cert-init` exports the
#     certificate into the task before the node starts. It terminated at the
#     load balancer for one day and that cost the client certificate —
#     deploy/aws/CLAUDE.md, *TLS passes through the NLB*
#   * (NOT ANY LONGER: its PORTS. The CRL/OCSP listener on 80 and the KDC on
#     TCP 88 were this file's until 2026-09-21, when rcbj asked that every
#     environment publish what this one does — they are the variables'
#     defaults now, so a temporary test environment and this one cannot
#     drift. `variables.tf` carries both arguments.)
#   * product mode with the request dispatcher — the `dispatch` row of
#     tests/tools/modes.sh with STS_MODE=product. THE BOOTSTRAP
#     ADMINISTRATOR'S PASSWORD IS IN SECRETS MANAGER (2026-09-17), at
#     mock-sts/testidp/bootstrap-admin-password, and is printed nowhere; it
#     was a log line in whichever node won the bootstrap claim until then.
#   * larger nodes: five node processes per task (front, three request
#     workers, one surface worker)
#   * no suite runner. Backups are deleted with the environment: it is
#     rebuilt many times over the coming weeks, and kept backups would pile up, billed.
# ---------------------------------------------------------------------------
public_hostname  = "test-idp.iyasec.io"
public_zone_name = "iyasec.io"

# The service's own names under iyasec.io rather than the example domains the
# settings default to (2026-09-18): the default realm's DNS domain (which roots
# the directory at dc=iyasec,dc=io — it was LDAP_BASE_DN until global.domain
# replaced that setting the same day), the Kerberos realm
# (whose lower-cased form is the domain the auto-created service principals and
# the PAC's domain name come from), the acceptor's service principal on the
# public host name, and the SPIFFE trust domain. `dev` and `ci` keep the
# defaults the suite is written against. None of the four can be changed under
# a store that already holds the old names — the directory, the Kerberos keys
# (salted with the realm) and the certificate authority (whose certificates
# name the directory copy of each CRL by DN) were all written under them — so
# the first apply carrying them REPLACED THE DATABASE (deploy/aws/CLAUDE.md).
extra_environment = {
  STS_DOMAIN              = "iyasec.io"
  KRB5_REALM              = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL  = "HTTP/test-idp.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN = "iyasec.io"
}

sts_mode                = "product"
workers_request_count   = 3
workers_surface_count   = 1
workers_dispatch        = "*"
workers_read_your_write = true

task_cpu    = 2048
task_memory = 8192

delete_automated_backups = true
vpc_cidr                 = "10.52.0.0/16"

tags = {
  ManagedBy = "terraform"
  Stack     = "mock-sts-environment"
  Lifecycle = "long-lived"
}
