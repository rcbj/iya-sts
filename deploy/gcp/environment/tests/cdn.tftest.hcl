# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THE CDN (#1341, cdn.tf): `terraform test` with the
# google and random providers MOCKED, so nothing is read from or made in GCP
# and no credential is needed. It holds what would fail quietly:
#
#   * single-region: Cloud CDN on the static backend only, caching by the
#     origin's headers with negative caching off; the API backend neither
#     cached nor compressed; X-Forwarded-Host and -Proto replaced; the
#     allowlist at the backend and at the edge; the nodes trusting Google's
#     front ends and naming the direct host for revocation; the node's own
#     public name mapped to the passthrough address;
#   * nothing changes without `cdn_enabled`;
#   * a GCP cell behind CloudFront (#97): the edges' ranges, the origin
#     secret's copy, the direct name on the certificate, and nothing of Cloud
#     CDN's made;
#   * `cdn_enabled` without a direct name is refused.
#
#   terraform -chdir=deploy/gcp/environment init -backend=false
#   terraform -chdir=deploy/gcp/environment test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "google" {
  mock_data "google_compute_zones" {
    defaults = { names = ["us-west1-a", "us-west1-b", "us-west1-c"] }
  }
  mock_data "google_service_account" {
    defaults = {
      email  = "iya-sts-env-testidp@p.iam.gserviceaccount.com"
      member = "serviceAccount:iya-sts-env-testidp@p.iam.gserviceaccount.com"
    }
  }
  mock_data "google_compute_image" {
    defaults = { self_link = "https://www.googleapis.com/compute/v1/projects/cos-cloud/global/images/cos" }
  }
  mock_data "google_dns_managed_zone" {
    defaults = { name = "gcp-iyasec-io" }
  }
  mock_resource "google_compute_global_address" {
    defaults = { address = "34.120.0.10" }
  }
  mock_resource "google_compute_address" {
    defaults = { address = "35.200.0.20" }
  }
}

mock_provider "random" {}

override_data {
  target = data.google_kms_crypto_key.kek
  values = { id = "projects/p/locations/us-west1/keyRings/iya-sts/cryptoKeys/iya-sts-kek" }
}

variables {
  project_id    = "p"
  environment   = "testidp"
  image_tag     = "t"
  allowed_cidrs = ["203.0.113.4/32"]
}

run "testidp_behind_cloud_cdn" {
  command = apply
  variables {
    public_hostname = "test-idp.gcp.iyasec.io"
    acme_email      = "tester1@iyasec.io"
    cdn_enabled     = true
    direct_hostname = "direct.test-idp.gcp.iyasec.io"
  }
  assert {
    condition     = google_compute_backend_service.api[0].enable_cdn == false && google_compute_backend_service.api[0].compression_mode == null
    error_message = "An API or protocol answer is neither cached nor compressed at the edge (BREACH)."
  }
  assert {
    condition     = google_compute_backend_service.static[0].enable_cdn && google_compute_backend_service.static[0].cdn_policy[0].cache_mode == "USE_ORIGIN_HEADERS" && google_compute_backend_service.static[0].cdn_policy[0].negative_caching == false
    error_message = "The static surfaces are cached as the origin says, and no error is."
  }
  assert {
    condition     = toset([for h in google_compute_url_map.cdn[0].header_action[0].request_headers_to_add : "${h.header_name}=${h.header_value}:${h.replace}"]) == toset(["X-Forwarded-Host=test-idp.gcp.iyasec.io:true", "X-Forwarded-Proto=https:true"])
    error_message = "A viewer's X-Forwarded-Host and -Proto must be replaced."
  }
  assert {
    condition     = google_compute_url_map.cdn[0].path_matcher[0].route_rules[0].match_rules[0].regex_match == local.cdn_static_regex && can(regex(local.cdn_static_regex, "/realm/acme/web/brand.css")) && can(regex(local.cdn_static_regex, "/admin/console.js")) && !can(regex(local.cdn_static_regex, "/oauth2/token"))
    error_message = "Only the static surfaces reach the CDN backend."
  }
  assert {
    condition     = google_compute_backend_service.static[0].edge_security_policy != null && length(google_compute_security_policy.allowlist[0].rule) == 2
    error_message = "The allowlist is at the backend and at the edge."
  }
  assert {
    condition     = one(google_dns_record_set.public[0].rrdatas) == "34.120.0.10" && one(google_dns_record_set.direct[0].rrdatas) == "35.200.0.20"
    error_message = "The public name is the CDN's; the direct name is the passthrough load balancer's."
  }
  assert {
    condition = alltrue([for n in ["node-a", "node-b", "node-c"] :
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_TRUST_PROXY=true\n") &&
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_TRUSTED_PROXIES=35.191.0.0/16,130.211.0.0/22,34.120.0.10/32\n") &&
      !strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_EDGE_PROXIES") &&
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "PKI_DISTRIBUTION_BASE_URL=http://direct.test-idp.gcp.iyasec.io\n") &&
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "--add-host test-idp.gcp.iyasec.io:35.200.0.20") &&
      strcontains(google_compute_instance_template.node[n].metadata["user-data"], "STS_TLS_ALT_NAMES=direct.test-idp.gcp.iyasec.io")
    ])
    error_message = "Every node trusts Google's front ends, names the direct host, and calls itself locally."
  }
}

run "no_cdn_by_default" {
  command = apply
  variables {
    public_hostname = "test-idp.gcp.iyasec.io"
    acme_email      = "tester1@iyasec.io"
  }
  assert {
    condition     = length(google_compute_global_address.cdn) == 0 && length(google_dns_record_set.direct) == 0 && one(google_dns_record_set.public[0].rrdatas) == "35.200.0.20"
    error_message = "Nothing of the CDN is made without cdn_enabled."
  }
  assert {
    condition     = strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_TRUSTED_PROXIES=\n") && !strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_TRUST_PROXY") && !strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "--add-host test-idp.gcp.iyasec.io")
    error_message = "A node behind no CDN trusts no proxy, as before."
  }
}

run "cell_behind_cloudfront" {
  command = apply
  variables {
    environment     = "testidpmc"
    kek_provider    = "secret"
    cell            = "gusw1"
    public_hostname = "test-idp.iyasec.io"
    acme_email      = "tester1@iyasec.io"
    cdn_enabled     = true
    direct_hostname = "direct.test-idp.iyasec.io"
    primary_cell    = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("../../multicloud/envs/testidpmc.cells.tfvars.json")).cells
  }
  override_data {
    target = data.terraform_remote_state.global[0]
    values = { outputs = {
      writer_address = "w", db_port = 5432, db_name = "sts", db_app_user = "sts_app",
      publication    = "sts_global", repl_user = "sts_repl", writer_ca_pem = "",
      secret_names = {
        "global-db-app-password" = "projects/p/secrets/iya-sts-testidpmc-global-global-db-app-password"
        "edge-secret"            = "projects/p/secrets/iya-sts-testidpmc-global-edge-secret"
      }
      copies           = { gusw1 = { hostname = "c", address = "10.0.0.9", ca_pem = "", master_secret = "m" } }
      cloudfront_cidrs = ["192.0.2.0/24"]
    } }
  }
  assert {
    condition     = length(google_compute_global_address.cdn) == 0 && length(google_compute_backend_service.static) == 0
    error_message = "A cell's CDN is CloudFront; nothing of Cloud CDN is made."
  }
  assert {
    condition = (strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_EDGE_PROXIES=192.0.2.0/24\n") &&
      strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_TRUSTED_PROXIES=192.0.2.0/24\n") &&
      strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_EDGE_SECRET=projects/p/secrets/iya-sts-testidpmc-global-edge-secret") &&
    strcontains(google_compute_instance_template.node["node-a"].metadata["user-data"], "STS_TLS_ALT_NAMES=gusw1.test-idp.iyasec.io,direct.test-idp.iyasec.io"))
    error_message = "A cell behind CloudFront believes its edges, requires the secret, and presents the direct name."
  }
}

run "cdn_without_a_direct_name_refused" {
  command = plan
  variables {
    public_hostname = "test-idp.gcp.iyasec.io"
    acme_email      = "tester1@iyasec.io"
    cdn_enabled     = true
  }
  expect_failures = [var.cdn_enabled]
}
