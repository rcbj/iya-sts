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
#   * the plain-HTTP CRL/OCSP listener published on PORT 80 rather than 8082,
#     which is where a relying party expects an http:// address it read out of
#     a certificate. The container is still on 8082; the front-end port is what
#     goes inside every certificate this service signs
#     (`PKI_DISTRIBUTION_BASE_URL`, ecs.tf), so `http://test-idp.iyasec.io/pki/
#     …` is what a client follows
#   * the KDC published on TCP 88 (publish_kerberos), so a Kerberos client
#     can reach it directly as well as over MS-KKDCP at /KdcProxy on 443
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

# The front-end port for the plain-HTTP CRL/OCSP/caIssuers listener. The
# container stays on 8082; `dev` and `ci` keep 8082 on both sides.
pki_listener_port = 80

# The KDC on TCP 88, through the load balancer like every other port
# (2026-09-18). TCP only — see the variable. `dev` and `ci` do not publish it.
publish_kerberos = true

# The service's own names under iyasec.io rather than the example domains the
# settings default to (2026-09-18): the directory's base DN, the Kerberos realm
# (whose lower-cased form is the domain the auto-created service principals and
# the PAC's domain name come from), the acceptor's service principal on the
# public host name, and the SPIFFE trust domain. `dev` and `ci` keep the
# defaults the suite is written against. None of the four can be changed under
# a store that already holds the old names — the directory, the Kerberos keys
# (salted with the realm) and the certificate authority (whose certificates
# name the directory copy of each CRL by DN) were all written under them — so
# the first apply carrying them REPLACED THE DATABASE (deploy/aws/CLAUDE.md).
extra_environment = {
  LDAP_BASE_DN            = "dc=iyasec,dc=io"
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

suite_runner             = false
delete_automated_backups = true
vpc_cidr                 = "10.52.0.0/16"

tags = {
  ManagedBy = "terraform"
  Stack     = "mock-sts-environment"
  Lifecycle = "long-lived"
}
