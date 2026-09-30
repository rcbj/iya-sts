# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#96): `terraform test` against a MOCKED
# azurerm provider, every cell's state overridden, so nothing is read from or
# made in Azure. It holds the mesh, the replicas, the secret copies and the
# Traffic Manager tree for the two-region and the three-region environment.
#
#   terraform -chdir=deploy/azure/global init -backend=false
#   terraform -chdir=deploy/azure/global test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      subscription_id = "00000000-0000-0000-0000-000000000001"
    }
  }
  mock_data "azurerm_key_vault" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v"
    }
  }
  mock_data "azurerm_key_vault_key" {
    defaults = {
      versionless_id = "https://v.vault.azure.net/keys/mock-sts"
    }
  }
  mock_data "azurerm_user_assigned_identity" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/pg"
    }
  }
  mock_data "azurerm_resource_group" {
    defaults = {
      name = "mock-sts-env-global"
    }
  }
  mock_data "azurerm_dns_zone" {
    defaults = {
      name                = "azure.iyasec.io"
      resource_group_name = "mock-sts-foundation"
    }
  }
  mock_resource "azurerm_postgresql_flexible_server" {
    defaults = {
      id   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/w"
      fqdn = "w.postgres.database.azure.com"
    }
  }
  mock_resource "azurerm_traffic_manager_profile" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/trafficManagerProfiles/tm"
    }
  }
}

override_data {
  target = data.terraform_remote_state.cell
  values = { outputs = {
    resource_group    = "mock-sts-env-cell"
    vnet_id           = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
    vnet_name         = "vnet"
    private_subnet_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/private"
    nodes_nsg_name    = "nsg"
    lb_public_ip_id   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/lb"
    outbound_address  = "20.9.9.9"
    container_ports   = ["389", "636", "8081", "8082", "8092", "8181", "88"]
  } }
}

variables {
  subscription_id       = "00000000-0000-0000-0000-000000000001"
  state_storage_account = "mockststate0000000000000"
}

run "testidpna" {
  variables {
    environment     = "testidpna"
    public_hostname = jsondecode(file("../environment/envs/testidpna.cells.tfvars.json")).public_hostname
    primary_cell    = jsondecode(file("../environment/envs/testidpna.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("../environment/envs/testidpna.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("../environment/envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  assert {
    condition     = length(azurerm_virtual_network_peering.cells) == 2 && jsonencode(keys(azurerm_postgresql_flexible_server.replica)) == jsonencode(["zcnc"])
    error_message = "one peering (two halves) and one replica, in zcnc"
  }
  assert {
    condition     = azurerm_private_endpoint.global["zwus2"].ip_configuration[0].private_ip_address == "10.82.10.12" && azurerm_private_endpoint.global["zcnc"].ip_configuration[0].private_ip_address == "10.83.10.12"
    error_message = "each cell's global endpoint at .12 of its private subnet"
  }
  assert {
    condition     = length(azurerm_key_vault_secret.global) == 13 && contains(keys(azurerm_key_vault_secret.global), "zwus2-global-db-master-password") && !contains(keys(azurerm_key_vault_secret.global), "zcnc-global-db-master-password")
    error_message = jsonencode(keys(azurerm_key_vault_secret.global))
  }
  assert {
    condition     = jsonencode(sort(keys(azurerm_traffic_manager_profile.child))) == jsonencode(["ca", "world"]) && jsonencode(azurerm_traffic_manager_nested_endpoint.child["ca"].geo_mappings) == jsonencode(["CA"])
    error_message = "a child per pinned jurisdiction, and the world"
  }
  assert {
    condition     = jsonencode(azurerm_traffic_manager_nested_endpoint.child["world"].geo_mappings) == jsonencode(["WORLD"]) && length(azurerm_traffic_manager_azure_endpoint.cell) == 3
    error_message = "world over both cells, ca over zcnc"
  }
  assert {
    condition     = azurerm_dns_cname_record.public[0].name == "na-idp"
    error_message = "the public name, relative to the zone"
  }
}

run "globalidp" {
  variables {
    environment     = "globalidp"
    public_hostname = jsondecode(file("../environment/envs/globalidp.cells.tfvars.json")).public_hostname
    primary_cell    = jsondecode(file("../environment/envs/globalidp.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("../environment/envs/globalidp.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("../environment/envs/globalidp.cells.tfvars.json")).jurisdictions
  }
  assert {
    condition     = length(azurerm_virtual_network_peering.cells) == 6 && jsonencode(sort(keys(azurerm_postgresql_flexible_server.replica))) == jsonencode(["zgwc", "zsea"])
    error_message = "a full mesh of three (six halves), two replicas"
  }
  assert {
    condition     = azurerm_postgresql_flexible_server.replica["zsea"].location == "southeastasia" && azurerm_postgresql_flexible_server.writer.location == "westus2"
    error_message = "each replica in its cell's region"
  }
  assert {
    condition     = jsonencode(sort(keys(azurerm_traffic_manager_profile.child))) == jsonencode(["eu", "sg", "world"]) && length(azurerm_traffic_manager_nested_endpoint.child["eu"].geo_mappings) == 30
    error_message = "the EU 27 and IS, LI, NO pinned to eu"
  }
  assert {
    condition     = length(azurerm_key_vault_secret.global) == 19 && length(azurerm_network_security_rule.cells_self) == 3
    error_message = "six shared secrets in each of three vaults and the master in one; a self rule per cell"
  }
}

run "one_cell_refused" {
  command = plan
  variables {
    environment  = "x1"
    primary_cell = "zwus2"
    cells        = { zwus2 = { region = "westus2", jurisdiction = "us", vpc_cidr = "10.1.0.0/16" } }
  }
  expect_failures = [var.cells]
}
