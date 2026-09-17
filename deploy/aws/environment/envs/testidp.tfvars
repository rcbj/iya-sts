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
#   * a public name and certificate — test-idp.iyasec.io, TLS ended at the
#     load balancer on an ACM certificate (dns.tf)
#   * product mode with the request dispatcher — the `dispatch` row of
#     tests/tools/modes.sh with STS_MODE=product. The bootstrap administrator's
#     password is logged ONCE by the node that wins the bootstrap claim.
#   * larger nodes: five node processes per task (front, three request
#     workers, one surface worker)
#   * no suite runner. Backups are deleted with the environment: it is
#     rebuilt many times over the coming weeks, and kept backups would pile up, billed.
# ---------------------------------------------------------------------------
public_hostname  = "test-idp.iyasec.io"
public_zone_name = "iyasec.io"

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
