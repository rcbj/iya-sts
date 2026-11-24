# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#1284): `terraform test` against a MOCKED
# azurerm provider, so nothing is read from or made in Azure and no
# credential is needed. It applies — to the mock — the standalone PEP
# environment and holds its shape: its own network with private members
# behind one NAT gateway, Application Gateway WAF_v2 with its policy (the
# negated allowlist, the rate limit, OWASP 3.2 and the bot set, Prevention),
# cookie affinity on the proxy, no key in custom data, the optional nudge,
# the companion, the trust anchor, shared and autoscale, and the refusals.
#
#   terraform -chdir=deploy/azure/pep-cluster init -backend=false
#   terraform -chdir=deploy/azure/pep-cluster test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      subscription_id = "00000000-0000-0000-0000-000000000001"
      tenant_id       = "00000000-0000-0000-0000-000000000002"
      object_id       = "00000000-0000-0000-0000-000000000003"
    }
  }
  mock_data "azurerm_resource_group" {
    defaults = { name = "iya-sts-testpep" }
  }
  mock_data "azurerm_key_vault" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.KeyVault/vaults/mptestpep-abcd"
      vault_uri = "https://mptestpep-abcd.vault.azure.net/"
    }
  }
  mock_data "azurerm_key_vault_certificate" {
    defaults = {
      versionless_secret_id = "https://mptestpep-abcd.vault.azure.net/secrets/gateway"
    }
  }
  mock_data "azurerm_user_assigned_identity" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.ManagedIdentity/userAssignedIdentities/members"
      client_id = "11111111-1111-1111-1111-111111111111"
    }
  }
  mock_data "azurerm_container_registry" {
    defaults = { login_server = "iyasts12345678.azurecr.io" }
  }
  mock_data "azurerm_dns_zone" {
    defaults = {
      name                = "azure.iyasec.io"
      resource_group_name = "iya-sts-foundation"
    }
  }
  mock_resource "azurerm_public_ip" {
    defaults = {
      id         = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.Network/publicIPAddresses/ip"
      ip_address = "20.1.2.3"
    }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.Network/virtualNetworks/vnet"
    }
  }
  mock_resource "azurerm_subnet" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet"
    }
  }
  mock_resource "azurerm_nat_gateway" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.Network/natGateways/nat"
    }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.Network/networkSecurityGroups/nsg"
    }
  }
  mock_resource "azurerm_web_application_firewall_policy" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/waf"
    }
  }
  mock_resource "azurerm_orchestrated_virtual_machine_scale_set" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/iya-sts-testpep/providers/Microsoft.Compute/virtualMachineScaleSets/member"
    }
  }
}

variables {
  subscription_id = "00000000-0000-0000-0000-000000000001"
  environment     = "testpep"
  idp_url         = "https://test-idp.azure.iyasec.io/"
  public_hostname = "test-pep.azure.iyasec.io"
  allowed_cidrs   = ["203.0.113.4/32"]
  image_tag       = "abc123def456"
  acme_email      = "tester1@iyasec.io"
}

run "a_network_of_its_own_with_private_members_behind_one_nat" {
  assert {
    condition     = azurerm_virtual_network.main.address_space == toset(["10.62.0.0/16"])
    error_message = "its own VNet"
  }
  assert {
    condition     = azurerm_subnet.members.default_outbound_access_enabled == false
    error_message = "the members' subnet has no default outbound access: out through the NAT gateway only"
  }
  assert {
    condition     = azurerm_subnet_nat_gateway_association.members.subnet_id == azurerm_subnet.members.id
    error_message = "the members leave through the one NAT gateway"
  }
  assert {
    condition     = output.egress_ip == "20.1.2.3"
    error_message = "the egress address is an output, for the identity service to admit"
  }
  assert {
    condition = alltrue([
      for v in azurerm_orchestrated_virtual_machine_scale_set.member :
      alltrue([for n in v.network_interface : alltrue([for c in n.ip_configuration : length(c.public_ip_address) == 0])])
    ])
    error_message = "no member has a public address"
  }
  assert {
    condition     = keys(azurerm_orchestrated_virtual_machine_scale_set.member) == ["azure-pep-1", "azure-pep-2"]
    error_message = "two per-instance members by default, named <cluster>-pep-<n>"
  }
  assert {
    condition     = alltrue([for v in azurerm_orchestrated_virtual_machine_scale_set.member : v.instances == 1])
    error_message = "a per-instance member is one VM"
  }
  assert {
    condition     = azurerm_orchestrated_virtual_machine_scale_set.member["azure-pep-2"].zones == toset(["2"])
    error_message = "per-instance members are spread over the zones"
  }
}

run "the_members_security_group_admits_the_gateway_only" {
  assert {
    condition     = azurerm_network_security_rule.members["gateway"].source_address_prefix == "10.62.0.0/24"
    error_message = "the members admit the gateway's subnet"
  }
  assert {
    condition     = azurerm_network_security_rule.members["gateway"].destination_port_ranges == toset(["9443", "9543"])
    error_message = "on the PEP's two ports only — never the companion's 9700"
  }
  assert {
    condition     = azurerm_network_security_rule.members_deny.access == "Deny" && azurerm_network_security_rule.members_deny.priority == 4096
    error_message = "everything else in is denied, ahead of Azure's defaults"
  }
  assert {
    condition     = contains(keys(azurerm_network_security_rule.gateway), "gateway-manager")
    error_message = "Application Gateway v2's control plane is admitted on its subnet"
  }
}

run "the_waf_is_in_front_and_blocks_by_default" {
  assert {
    condition     = azurerm_application_gateway.main.sku[0].name == "WAF_v2" && azurerm_application_gateway.main.firewall_policy_id == azurerm_web_application_firewall_policy.main.id
    error_message = "Application Gateway WAF_v2, with the policy"
  }
  assert {
    condition     = azurerm_web_application_firewall_policy.main.policy_settings[0].mode == "Prevention"
    error_message = "the WAF blocks, not counts"
  }
  assert {
    condition = (
      azurerm_web_application_firewall_policy.main.custom_rules[0].name == "notallowed" &&
      azurerm_web_application_firewall_policy.main.custom_rules[0].action == "Block" &&
      azurerm_web_application_firewall_policy.main.custom_rules[0].match_conditions[0].negation_condition == true &&
      azurerm_web_application_firewall_policy.main.custom_rules[0].match_conditions[0].match_values == tolist(["203.0.113.4/32"])
    )
    error_message = "the allowlist is a NEGATED BLOCK, first: a custom allow would skip the managed rules"
  }
  assert {
    condition = (
      azurerm_web_application_firewall_policy.main.custom_rules[1].rule_type == "RateLimitRule" &&
      azurerm_web_application_firewall_policy.main.custom_rules[1].rate_limit_threshold == 2000
    )
    error_message = "a per-address rate limit"
  }
  assert {
    condition = toset([for s in azurerm_web_application_firewall_policy.main.managed_rules[0].managed_rule_set : "${s.type}/${s.version}"]) == toset([
      "OWASP/3.2", "Microsoft_BotManagerRuleSet/1.0",
    ])
    error_message = "the OWASP core set and the bot manager set"
  }
  assert {
    condition     = azurerm_web_application_firewall_policy.main.policy_settings[0].max_request_body_size_in_kb == 128
    error_message = "the request-body limit is the variable's"
  }
}

run "one_certificate_a_sticky_proxy_and_no_key_in_custom_data" {
  assert {
    condition     = one(azurerm_application_gateway.main.ssl_certificate).key_vault_secret_id == "https://mptestpep-abcd.vault.azure.net/secrets/gateway"
    error_message = "the listener certificate is the vault's version-less `gateway`"
  }
  assert {
    condition     = one([for b in azurerm_application_gateway.main.backend_http_settings : b if b.name == "proxy"]).cookie_based_affinity == "Enabled"
    error_message = "a browser stays on one member, by the gateway's cookie"
  }
  assert {
    condition     = one([for b in azurerm_application_gateway.main.backend_http_settings : b if b.name == "proxy"]).port == 9543
    error_message = "the proxy re-encrypted to the members' 9543"
  }
  assert {
    condition     = one(azurerm_application_gateway.main.probe).port == 9443 && one(azurerm_application_gateway.main.probe).path == "/healthcheck"
    error_message = "every backend asks the member's 9443 /healthcheck"
  }
  assert {
    condition = alltrue([
      for m, c in local.cloud_init :
      !strcontains(c, "PRIVATE KEY") && !strcontains(c, "BEGIN CERTIFICATE")
    ])
    error_message = "nothing PEM is in a member's custom data"
  }
  assert {
    condition     = strcontains(local.cloud_init["azure-pep-1"], "secrets/$${secret}?api-version") && strcontains(local.cloud_init["azure-pep-1"], "secret=pep-azure-azure-pep-1")
    error_message = "the member reads its one secret from the vault at boot"
  }
  assert {
    condition     = output.gateway_trusts_members == false && length(azurerm_application_gateway.main.trusted_root_certificate) == 0
    error_message = "without the anchor the gateway trusts no member yet, and says so"
  }
}

run "the_members_pull_from_the_idp_and_member_1_issues" {
  assert {
    condition     = local.pep_environment["azure-pep-1"]["PEP_PDP_URL"] == "https://test-idp.azure.iyasec.io"
    error_message = "the identity service at its public URL"
  }
  assert {
    condition     = !contains(keys(local.pep_environment["azure-pep-2"]), "PEP_NOTIFY_URL")
    error_message = "with no notify_cidrs nothing advertises a nudge port"
  }
  assert {
    condition     = contains(keys(local.unit_files["azure-pep-1"]), "pep-cert.service") && !contains(keys(local.unit_files["azure-pep-2"]), "pep-cert.service")
    error_message = "only member 1 obtains the gateway's certificate"
  }
  assert {
    condition     = strcontains(local.unit_files["azure-pep-1"]["pep-cert.service"], "STS_ACME_KEY_TYPE=rsa2048")
    error_message = "the gateway's certificate is RSA"
  }
}

run "the_anchor_makes_the_gateway_trust_the_members" {
  variables {
    member_trust_anchor = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
  }

  assert {
    condition     = length(azurerm_application_gateway.main.trusted_root_certificate) == 1
    error_message = "the identity service's Root is the gateway's trusted root"
  }
  assert {
    condition     = one([for b in azurerm_application_gateway.main.backend_http_settings : b if b.name == "proxy"]).trusted_root_certificate_names == tolist(["member-root"])
    error_message = "and each backend verifies against it"
  }
}

run "the_nudge_when_the_idp_has_fixed_addresses" {
  variables {
    notify_cidrs = ["198.51.100.7/32"]
  }

  assert {
    condition     = toset([for p in azurerm_application_gateway.main.frontend_port : p.port if startswith(p.name, "notify-")]) == toset([9451, 9452])
    error_message = "each member's nudge has a port of its own"
  }
  assert {
    condition     = local.pep_environment["azure-pep-2"]["PEP_NOTIFY_URL"] == "https://test-pep.azure.iyasec.io:9452/notify"
    error_message = "a member advertises its own notify port at the public name"
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_network_security_rule.gateway :
      r.source_address_prefix == "198.51.100.7/32" if startswith(k, "notify-")
    ])
    error_message = "the notify ports admit the identity service only"
  }
  assert {
    condition     = contains(azurerm_web_application_firewall_policy.main.custom_rules[0].match_conditions[0].match_values, "198.51.100.7/32")
    error_message = "the WAF's allowlist admits the identity service's address too"
  }
}

run "the_companion_is_on_the_members_loopback" {
  variables {
    companion = true
  }

  assert {
    condition     = alltrue([for m, f in local.unit_files : contains(keys(f), "pep-companion.service")])
    error_message = "every member runs its own companion"
  }
  assert {
    condition     = output.companion_upstream == "http://127.0.0.1:9700"
    error_message = "the route's upstream is each member's own loopback"
  }
  assert {
    condition     = !anytrue([for r in azurerm_network_security_rule.members : contains(r.destination_port_ranges, "9700")])
    error_message = "no rule admits the companion's port"
  }
}

run "shared_autoscales_when_asked" {
  variables {
    credential_mode = "shared"
    instance_count  = 2
    autoscale_max   = 6
  }

  assert {
    condition     = keys(azurerm_orchestrated_virtual_machine_scale_set.member) == ["azure-pep"] && azurerm_orchestrated_virtual_machine_scale_set.member["azure-pep"].instances == 2
    error_message = "one member name, two VMs"
  }
  assert {
    condition     = azurerm_monitor_autoscale_setting.shared[0].profile[0].capacity[0].maximum == 6
    error_message = "the count is the floor, autoscale_max the ceiling"
  }
}

run "a_realm_prefixes_the_pdp_url" {
  variables {
    realm = "acme"
  }

  assert {
    condition     = output.pdp_url == "https://test-idp.azure.iyasec.io/realm/acme"
    error_message = "a realm's members pull from its prefix"
  }
}

run "autoscale_is_refused_per_instance" {
  command = plan

  variables {
    autoscale_max = 4
  }

  expect_failures = [azurerm_orchestrated_virtual_machine_scale_set.member]
}

run "a_name_outside_the_zone_is_refused" {
  command = plan

  variables {
    public_hostname = "test-pep.example.test"
  }

  expect_failures = [azurerm_application_gateway.main]
}
