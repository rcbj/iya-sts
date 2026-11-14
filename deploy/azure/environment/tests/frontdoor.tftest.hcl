# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF FRONT DOOR (#1341, frontdoor.tf): `terraform test`
# against a MOCKED azurerm provider (render.tftest.hcl's mocks, and three of
# Front Door's own). It holds what would fail quietly: the route caches and
# compresses nothing and serves the public name only; the static surfaces
# alone are cached, as the origin says; the origin is the direct name with
# the public name as its Host; the allowlist reads the connecting address;
# the nodes believe the edges and require the origin secret, which a cell
# reads from its vault; one profile per environment, the primary cell's, in
# `full`.
#
#   terraform -chdir=deploy/azure/environment init -backend=false
#   terraform -chdir=deploy/azure/environment test
# ---------------------------------------------------------------------------
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      subscription_id = "00000000-0000-0000-0000-000000000001"
      tenant_id       = "00000000-0000-0000-0000-000000000002"
      object_id       = "00000000-0000-0000-0000-000000000003"
    }
  }
  mock_data "azurerm_key_vault" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/msvault-abcd"
      vault_uri = "https://msvault-abcd.vault.azure.net/"
    }
  }
  mock_data "azurerm_user_assigned_identity" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/nodes"
      client_id = "11111111-1111-1111-1111-111111111111"
    }
  }
  mock_data "azurerm_container_registry" {
    defaults = {
      login_server = "iyasts12345678.azurecr.io"
    }
  }
  mock_data "azurerm_dns_zone" {
    defaults = {
      id                  = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-foundation/providers/Microsoft.Network/dnsZones/azure.iyasec.io"
      name                = "azure.iyasec.io"
      resource_group_name = "iya-sts-foundation"
    }
  }
  mock_data "azurerm_resource_group" {
    defaults = {
      name = "iya-sts-unit"
    }
  }
  mock_resource "azurerm_postgresql_flexible_server" {
    defaults = {
      id   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/primary"
      fqdn = "iya-sts-primary-abcdef.postgres.database.azure.com"
    }
  }
  mock_resource "azurerm_public_ip" {
    defaults = {
      id         = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/lb"
      ip_address = "20.1.2.3"
    }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
    }
  }
  mock_resource "azurerm_subnet" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet"
    }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
    }
  }
  mock_resource "azurerm_lb" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb"
    }
  }
  mock_resource "azurerm_lb_backend_address_pool" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/nodes"
    }
  }
  mock_resource "azurerm_lb_probe" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/probes/https"
    }
  }
  mock_resource "azurerm_orchestrated_virtual_machine_scale_set" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss"
    }
  }
  mock_data "azurerm_key_vault_key" {
    defaults = {
      versionless_id = "https://mskwus2-abcdef.vault.azure.net/keys/iya-sts"
    }
  }
  mock_data "azurerm_disk_encryption_set" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des"
    }
  }
  mock_data "azurerm_network_service_tags" {
    defaults = {
      ipv4_cidrs = ["198.51.100.0/24"]
    }
  }
  mock_resource "azurerm_cdn_frontdoor_profile" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd"
    }
  }
  mock_resource "azurerm_cdn_frontdoor_endpoint" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd/afdEndpoints/fd"
      host_name = "iya-sts-testidp-fd-abc123.z01.azurefd.net"
    }
  }
  mock_resource "azurerm_cdn_frontdoor_origin_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd/originGroups/direct"
    }
  }
  mock_resource "azurerm_cdn_frontdoor_origin" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd/originGroups/direct/origins/direct"
    }
  }
  mock_resource "azurerm_cdn_frontdoor_rule_set" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd/ruleSets/iyasts"
    }
  }
  mock_resource "azurerm_cdn_frontdoor_custom_domain" {
    defaults = {
      id               = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd/customDomains/public"
      validation_token = "tok"
    }
  }
  mock_resource "azurerm_cdn_frontdoor_route" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd/afdEndpoints/fd/routes/public"
    }
  }
  mock_resource "azurerm_cdn_frontdoor_firewall_policy" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/allowlist"
    }
  }
  mock_data "azurerm_monitor_data_collection_rule" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionRules/syslog"
    }
  }

}

variables {
  subscription_id = "00000000-0000-0000-0000-000000000001"
  allowed_cidrs   = ["203.0.113.7/32"]
  image_tag       = "abc1234"
}

run "testidp_behind_front_door" {
  variables {
    environment     = "testidp"
    public_hostname = "test-idp.azure.iyasec.io"
    direct_hostname = "direct.test-idp.azure.iyasec.io"
    cdn_enabled     = true
    acme_email      = "tester1@iyasec.io"
    vpc_cidr        = "10.81.0.0/16"
  }
  assert {
    condition     = length(azurerm_cdn_frontdoor_route.main[0].cache) == 0 && azurerm_cdn_frontdoor_route.main[0].link_to_default_domain == false && azurerm_cdn_frontdoor_route.main[0].forwarding_protocol == "HttpsOnly"
    error_message = "The route caches and compresses nothing, and serves the public name only."
  }
  assert {
    condition     = azurerm_cdn_frontdoor_rule.static_files[0].actions[0].route_configuration_override_action[0].cache_behavior == "HonorOrigin" && azurerm_cdn_frontdoor_rule.static_web[0].actions[0].route_configuration_override_action[0].compression_enabled && can(regex(local.frontdoor_static_regex, "/realm/acme/web/brand.css")) && !can(regex(local.frontdoor_static_regex, "/oauth2/token"))
    error_message = "Only the static surfaces are cached, as the origin says."
  }
  assert {
    condition     = azurerm_cdn_frontdoor_origin.main[0].host_name == "direct.test-idp.azure.iyasec.io" && azurerm_cdn_frontdoor_origin.main[0].origin_host_header == "test-idp.azure.iyasec.io" && azurerm_cdn_frontdoor_origin.main[0].certificate_name_check_enabled
    error_message = "The origin is the direct name, with the public name as its Host."
  }
  assert {
    condition     = azurerm_cdn_frontdoor_firewall_policy.allowlist[0].custom_rule[0].match_condition[0].match_variable == "SocketAddr" && azurerm_cdn_frontdoor_firewall_policy.allowlist[0].custom_rule[0].match_condition[0].negation_condition
    error_message = "The allowlist reads the connecting address, never a forwarded header."
  }
  assert {
    condition     = azurerm_dns_a_record.public[0].name == "direct.test-idp" && azurerm_dns_cname_record.frontdoor[0].name == "test-idp" && azurerm_dns_txt_record.frontdoor_validation[0].name == "_dnsauth.test-idp"
    error_message = "The public name is Front Door's; the direct name is the load balancer's."
  }
  assert {
    condition     = local.node_environment.STS_TRUST_PROXY == "true" && local.node_environment.STS_EDGE_PROXIES == "198.51.100.0/24" && local.node_secret_env.STS_EDGE_SECRET == "edge-secret" && contains(keys(local.secrets), "edge-secret")
    error_message = "The nodes believe the edges and require the origin secret."
  }
  assert {
    condition     = strcontains(local.extra_hosts, "--add-host test-idp.azure.iyasec.io:20.1.2.3") && strcontains(local.pki_public_url, "direct.test-idp.azure.iyasec.io") && contains(keys(azurerm_network_security_rule.rules), "nodes-front-door")
    error_message = "A node calls itself locally, revocation is at the direct name, and the edges are admitted."
  }
}

run "no_front_door_by_default" {
  variables {
    environment     = "testidp"
    public_hostname = "test-idp.azure.iyasec.io"
    acme_email      = "tester1@iyasec.io"
    vpc_cidr        = "10.81.0.0/16"
  }
  assert {
    condition     = length(azurerm_cdn_frontdoor_profile.main) == 0 && azurerm_dns_a_record.public[0].name == "test-idp" && local.node_environment.STS_TRUSTED_PROXIES == "" && !contains(keys(local.node_environment), "STS_TRUST_PROXY") && !contains(keys(local.node_secret_env), "STS_EDGE_SECRET")
    error_message = "Nothing changes without cdn_enabled."
  }
}

run "testidpna_primary_holds_the_profile" {
  variables {
    environment     = "testidpna"
    cell            = "zwus2"
    cdn_enabled     = true
    public_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).public_hostname
    direct_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).direct_hostname
    acme_email      = "tester1@iyasec.io"
    primary_cell    = jsondecode(file("envs/testidpna.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("envs/testidpna.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  override_data {
    target = data.terraform_remote_state.global
    values = { outputs = {
      writer_host = "w.postgres.database.azure.com"
      read_hosts  = { zwus2 = "w.postgres.database.azure.com", zcnc = "r.postgres.database.azure.com" }
      db_port     = 5432, db_name = "sts", db_app_user = "sts_app", edge_secret = "s3cret"
    } }
  }
  assert {
    condition     = length(azurerm_cdn_frontdoor_profile.main) == 1 && azurerm_cdn_frontdoor_origin.main[0].host_name == "direct.na-idp.azure.iyasec.io" && azurerm_dns_cname_record.frontdoor[0].name == "na-idp"
    error_message = "The primary holds the one profile; its origin is the Traffic Manager tree at the direct name."
  }
  assert {
    condition     = local.node_secret_env.STS_EDGE_SECRET == "edge-secret" && !contains(keys(local.secrets), "edge-secret")
    error_message = "A cell reads the global tier's copy of the secret from its vault."
  }
}

run "testidpna_other_cell_has_no_profile" {
  variables {
    environment     = "testidpna"
    cell            = "zcnc"
    cdn_enabled     = true
    public_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).public_hostname
    direct_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).direct_hostname
    acme_email      = "tester1@iyasec.io"
    primary_cell    = jsondecode(file("envs/testidpna.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("envs/testidpna.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  override_data {
    target = data.terraform_remote_state.global
    values = { outputs = {
      writer_host = "w.postgres.database.azure.com"
      read_hosts  = { zwus2 = "w.postgres.database.azure.com", zcnc = "r.postgres.database.azure.com" }
      db_port     = 5432, db_name = "sts", db_app_user = "sts_app", edge_secret = "s3cret"
    } }
  }
  assert {
    condition     = length(azurerm_cdn_frontdoor_profile.main) == 0 && local.node_environment.STS_EDGE_PROXIES == "198.51.100.0/24" && strcontains(local.unit_files["node-a"]["sts-cert.service"], "direct.na-idp.azure.iyasec.io")
    error_message = "Every cell believes the edges and presents the direct name; only the primary holds the profile."
  }
}

run "testidpna_primary_base_has_no_profile" {
  variables {
    environment     = "testidpna"
    cell            = "zwus2"
    cell_phase      = "base"
    cdn_enabled     = true
    public_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).public_hostname
    direct_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).direct_hostname
    acme_email      = "tester1@iyasec.io"
    primary_cell    = jsondecode(file("envs/testidpna.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("envs/testidpna.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  assert {
    condition     = length(azurerm_cdn_frontdoor_profile.main) == 0 && !contains(keys(local.node_secret_env), "STS_EDGE_SECRET")
    error_message = "No profile and no secret read before the global tier holds it."
  }
}
