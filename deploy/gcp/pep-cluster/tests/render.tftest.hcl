# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THE GCP REMOTE PEP CLUSTER (#1284): `terraform test`
# with the google provider MOCKED, so nothing is read from or made in GCP and
# no credential is needed — deploy/aws/pep-cluster/tests/render.tftest.hcl's
# runs, on GCP's parts. It holds:
#
#   * an environment of its own: its own VPC, the members without an external
#     address, ONE reserved NAT address;
#   * Cloud Armor: the WAF signatures and the rate limit BEFORE the allowlist,
#     default deny, on every backend;
#   * the proxy's GENERATED_COOKIE affinity and the decision API's none, both
#     health-checked on the member's 9443;
#   * no key in metadata, only secret references to files on a tmpfs;
#   * the decision API and the nudge by NAME, the companion sidecar, shared
#     mode with its autoscaler, a realm, and the refusals.
#
#   terraform -chdir=deploy/gcp/pep-cluster init -backend=false
#   terraform -chdir=deploy/gcp/pep-cluster test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "google" {
  mock_data "google_compute_zones" {
    defaults = { names = ["us-west1-b", "us-west1-a", "us-west1-c"] }
  }
  mock_data "google_compute_image" {
    defaults = { self_link = "https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos" }
  }
  mock_data "google_kms_crypto_key" {
    defaults = { id = "projects/p/locations/us-west1/keyRings/iya-sts/cryptoKeys/iya-sts" }
  }
  mock_data "google_service_account" {
    defaults = {
      email  = "iya-sts-pep-testpep@p.iam.gserviceaccount.com"
      member = "serviceAccount:iya-sts-pep-testpep@p.iam.gserviceaccount.com"
    }
  }
  mock_data "google_dns_managed_zone" {
    defaults = { name = "gcp-iyasec-io" }
  }
  mock_data "google_secret_manager_secret" {
    defaults = { id = "projects/p/secrets/iya-sts-testpep-pep-aws-m-part" }
  }
  mock_resource "google_compute_address" {
    defaults = { address = "35.200.0.9", self_link = "https://www.googleapis.com/compute/v1/projects/p/regions/us-west1/addresses/iya-sts-testpep-egress" }
  }
  mock_resource "google_compute_global_address" {
    defaults = { address = "34.120.0.10" }
  }
  mock_resource "google_compute_instance_group_manager" {
    defaults = { instance_group = "https://www.googleapis.com/compute/v1/projects/p/zones/us-west1-a/instanceGroups/g" }
  }
  mock_resource "google_compute_region_instance_group_manager" {
    defaults = { instance_group = "https://www.googleapis.com/compute/v1/projects/p/regions/us-west1/instanceGroups/g" }
  }
}

variables {
  project_id        = "p"
  environment       = "testpep"
  image_tag         = "t"
  idp_url           = "https://test-idp.gcp.iyasec.io/"
  public_hostname   = "test-pep.gcp.iyasec.io"
  decision_hostname = "decision.test-pep.gcp.iyasec.io"
  allowed_cidrs     = ["203.0.113.4/32"]
}

run "an_environment_of_its_own_with_private_members" {
  command = apply

  assert {
    condition     = google_compute_network.main.name == "iya-sts-testpep" && !google_compute_network.main.auto_create_subnetworks
    error_message = "Its own VPC."
  }
  assert {
    condition     = alltrue([for t in google_compute_instance_template.member : length(t.network_interface[0].access_config) == 0])
    error_message = "No member has an external address."
  }
  assert {
    condition     = google_compute_router_nat.main.nat_ip_allocate_option == "MANUAL_ONLY" && length(google_compute_router_nat.main.nat_ips) == 1 && output.egress_ip == "35.200.0.9"
    error_message = "One reserved egress address, for the identity service to admit."
  }
  assert {
    condition     = keys(google_compute_instance_group_manager.member) == ["aws-pep-1", "aws-pep-2"] && alltrue([for g in google_compute_instance_group_manager.member : g.target_size == 1])
    error_message = "Two members, a group of one VM each."
  }
  assert {
    condition     = google_compute_instance_group_manager.member["aws-pep-1"].zone != google_compute_instance_group_manager.member["aws-pep-2"].zone
    error_message = "The members are spread round the zones."
  }
  assert {
    condition     = output.pdp_url == "https://test-idp.gcp.iyasec.io"
    error_message = "The identity service at its public URL."
  }
}

run "cloud_armor_in_front" {
  command = apply

  assert {
    condition     = google_compute_backend_service.proxy.security_policy == google_compute_security_policy.main.id && google_compute_backend_service.decision[0].security_policy == google_compute_security_policy.main.id
    error_message = "Every client backend is behind the policy."
  }
  assert {
    condition = length([
      for r in google_compute_security_policy.main.rule : r
      if length(r.match[0].expr) > 0 && can(regex("evaluatePreconfiguredWaf", r.match[0].expr[0].expression))
    ]) == 8
    error_message = "The eight preconfigured WAF rule sets."
  }
  assert {
    condition = (
      max([for r in google_compute_security_policy.main.rule : r.priority if r.action == "deny(403)" && length(r.match[0].expr) > 0]...) <
      min([for r in google_compute_security_policy.main.rule : r.priority if r.action == "allow"]...)
    )
    error_message = "An allowed address is still held to the signatures: they come before the allow."
  }
  assert {
    condition     = one([for r in google_compute_security_policy.main.rule : r.priority if r.action == "throttle"]) < min([for r in google_compute_security_policy.main.rule : r.priority if r.action == "allow"]...)
    error_message = "The rate limit comes before the allow."
  }
  assert {
    condition     = one([for r in google_compute_security_policy.main.rule : r.action if r.priority == 2147483647]) == "deny(403)"
    error_message = "What no rule allows is denied."
  }
}

run "a_sticky_proxy_and_one_managed_certificate" {
  command = apply

  assert {
    condition     = google_compute_backend_service.proxy.session_affinity == "GENERATED_COOKIE" && google_compute_backend_service.proxy.port_name == "proxy"
    error_message = "A browser stays on one member, by the load balancer's cookie."
  }
  assert {
    condition     = google_compute_backend_service.decision[0].session_affinity == "NONE" && google_compute_backend_service.decision[0].port_name == "decision"
    error_message = "The decision API is not sticky."
  }
  assert {
    condition     = google_compute_health_check.member.https_health_check[0].port == 9443 && google_compute_health_check.member.https_health_check[0].request_path == "/healthcheck"
    error_message = "Every backend asks the member's 9443 /healthcheck."
  }
  assert {
    condition     = toset(google_compute_managed_ssl_certificate.lb.managed[0].domains) == toset(["test-pep.gcp.iyasec.io", "decision.test-pep.gcp.iyasec.io"])
    error_message = "One certificate, for the public and decision names."
  }
  assert {
    condition     = flatten([for h in google_compute_url_map.main.host_rule : tolist(h.hosts)]) == ["decision.test-pep.gcp.iyasec.io"]
    error_message = "The decision API is told apart by name."
  }
}

run "no_key_in_metadata" {
  command = apply

  assert {
    condition = alltrue([
      for t in google_compute_instance_template.member :
      !strcontains(t.metadata["user-data"], "PRIVATE KEY") && !strcontains(t.metadata["user-data"], "BEGIN CERTIFICATE")
    ])
    error_message = "Nothing PEM is in instance metadata."
  }
  assert {
    condition     = strcontains(google_compute_instance_template.member["aws-pep-1"].metadata["user-data"], "sts-secret-files") && strcontains(google_compute_instance_template.member["aws-pep-1"].metadata["user-data"], "/run/pep")
    error_message = "The keys are read on the VM, into the tmpfs."
  }
  assert {
    condition     = length(google_secret_manager_secret_iam_member.member) == 8
    error_message = "Each member's account reads its four mounted secrets, one grant each."
  }
  assert {
    condition     = !strcontains(google_compute_instance_template.member["aws-pep-1"].metadata["user-data"], "PEP_NOTIFY_URL")
    error_message = "With no notify_cidrs nothing advertises a nudge."
  }
}

run "the_nudge_by_name_when_the_idp_has_fixed_addresses" {
  command = apply
  variables {
    notify_cidrs = ["198.51.100.7/32"]
  }

  assert {
    condition     = keys(google_compute_backend_service.notify) == ["aws-pep-1", "aws-pep-2"] && google_compute_backend_service.notify["aws-pep-1"].security_policy == google_compute_security_policy.notify[0].id
    error_message = "Each member has a notify backend of its own, held to notify_cidrs."
  }
  assert {
    condition     = strcontains(google_compute_instance_template.member["aws-pep-2"].metadata["user-data"], "PEP_NOTIFY_URL=https://aws-pep-2.test-pep.gcp.iyasec.io/notify")
    error_message = "A member advertises its own notify name."
  }
  assert {
    condition     = contains(google_compute_managed_ssl_certificate.lb.managed[0].domains, "aws-pep-1.test-pep.gcp.iyasec.io")
    error_message = "The notify names are on the certificate."
  }
}

run "the_companion_is_a_sidecar_nothing_admits" {
  command = apply
  variables {
    companion = true
  }

  assert {
    condition     = strcontains(google_compute_instance_template.member["aws-pep-1"].metadata["user-data"], "--network container:xacml-pep")
    error_message = "The companion shares the member's network namespace."
  }
  assert {
    condition     = !contains(flatten([for a in google_compute_firewall.health_checks.allow : a.ports]), "9700")
    error_message = "No rule admits the companion's port."
  }
  assert {
    condition     = output.companion_upstream == "http://127.0.0.1:9700"
    error_message = "The route's upstream is each member's own loopback."
  }
}

run "shared_autoscales_when_asked" {
  command = apply
  variables {
    credential_mode = "shared"
    instance_count  = 2
    autoscaling_max = 6
  }

  assert {
    condition     = length(google_compute_instance_group_manager.member) == 0 && length(google_compute_region_instance_group_manager.shared) == 1 && google_compute_region_autoscaler.shared[0].autoscaling_policy[0].max_replicas == 6
    error_message = "One regional group, two to six VMs."
  }
}

run "a_realm_prefixes_the_pdp_url" {
  command = apply
  variables {
    realm = "acme"
  }

  assert {
    condition     = output.pdp_url == "https://test-idp.gcp.iyasec.io/realm/acme"
    error_message = "A realm's members pull from its prefix."
  }
}

run "autoscaling_is_refused_per_instance" {
  command = plan
  variables {
    autoscaling_max = 4
  }
  expect_failures = [google_compute_instance_template.member]
}

run "the_decision_api_needs_a_name_of_its_own" {
  command = plan
  variables {
    decision_hostname = ""
  }
  expect_failures = [google_compute_instance_template.member]
}
