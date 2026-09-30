# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#96): `terraform test` against a MOCKED
# azurerm provider, so nothing is read from or made in Azure and no
# credential is needed. It applies — to the mock — the one-region `testidp`,
# a bare `dev`, a two-region cell in both phases and a three-region cell,
# and holds what each must render: the nodes, the published ports, the
# security rules, the database's endpoint, the cells' contract with the
# service, and the units a node is given.
#
#   terraform -chdir=deploy/azure/environment init -backend=false
#   terraform -chdir=deploy/azure/environment test
#
# Not run by the suite or CI; run it after changing this stack
# (deploy/azure/CLAUDE.md, *What was checked*).
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
      login_server = "mocksts12345678.azurecr.io"
    }
  }
  mock_data "azurerm_dns_zone" {
    defaults = {
      name                = "azure.iyasec.io"
      resource_group_name = "mock-sts-foundation"
    }
  }
  mock_data "azurerm_resource_group" {
    defaults = {
      name = "mock-sts-unit"
    }
  }
  mock_resource "azurerm_postgresql_flexible_server" {
    defaults = {
      id   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/primary"
      fqdn = "mock-sts-primary-abcdef.postgres.database.azure.com"
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
      versionless_id = "https://mskwus2-abcdef.vault.azure.net/keys/mock-sts"
    }
  }
  mock_data "azurerm_disk_encryption_set" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des"
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

run "dev" {
  variables {
    environment = "dev"
  }
  assert {
    condition     = length(local.nodes) == 3 && length(azurerm_orchestrated_virtual_machine_scale_set.others) == 2
    error_message = "three nodes: node-a and two others"
  }
  assert {
    condition     = length(azurerm_lb_rule.published) == 7 && azurerm_lb_rule.published["https"].backend_port == 8081 && azurerm_lb_rule.published["pki"].frontend_port == 80
    error_message = "the seven published ports, 443 to 8081"
  }
  assert {
    condition     = length(azurerm_dns_a_record.public) == 0 && local.public_base_url == "https://20.1.2.3"
    error_message = "no public name: the load balancer's address"
  }
  assert {
    condition     = local.node_environment.STS_KEYS_KEK_PROVIDER == "azure" && local.node_environment.STS_KEYS_KEK_VAULT == "https://msvault-abcd.vault.azure.net" && local.node_environment.STS_PROXY_PROTOCOL == "off"
    error_message = "the key from Key Vault, and no PROXY header"
  }
  assert {
    condition     = !contains(keys(local.node_environment), "STS_CELL_ID") && length(azurerm_lb.intercell) == 0
    error_message = "a single-cell environment has no cell contract and no inter-cell load balancer"
  }
  assert {
    condition     = strcontains(local.extra_hosts, "--add-host mock-sts-primary-abcdef.postgres.database.azure.com:10.80.10.10")
    error_message = local.extra_hosts
  }
  assert {
    condition     = local.key_kind == "main" && local.region_code == "wus2" && local.prefix == "mock-sts-dev"
    error_message = "the project key, in the home region"
  }
  assert {
    condition     = !contains(keys(local.unit_files["node-a"]), "sts-cert.service") && !contains(keys(local.unit_files["node-a"]), "sts-global-schema.service")
    error_message = "no certificate unit without a name, and no global schema outside a cell"
  }
  assert {
    condition     = contains(keys(azurerm_network_security_rule.rules), "nodes-deny-inbound") && !contains(keys(azurerm_network_security_rule.rules), "nodes-dns-out")
    error_message = "the deny rules, and no DNS egress without a public name"
  }
}

run "testidp" {
  variables {
    environment     = "testidp"
    public_hostname = "test-idp.azure.iyasec.io"
    acme_email      = "tester1@iyasec.io"
    sts_mode        = "product"
    vm_size         = "Standard_D2s_v5"
    vpc_cidr        = "10.81.0.0/16"
  }
  assert {
    condition     = azurerm_dns_a_record.public[0].name == "test-idp" && local.public_base_url == "https://test-idp.azure.iyasec.io"
    error_message = "the A record, relative to the zone"
  }
  assert {
    condition     = strcontains(local.unit_files["node-a"]["sts-cert.service"], "STS_CERT_ISSUER=true") && strcontains(local.unit_files["node-b"]["sts-cert.service"], "STS_CERT_ISSUER=false")
    error_message = "node-a alone issues the certificate"
  }
  assert {
    condition     = contains(keys(local.secrets), "bootstrap-admin-password") && contains(keys(local.secrets), "kek") && !contains(keys(local.secrets), "cell-kek")
    error_message = jsonencode(keys(local.secrets))
  }
  assert {
    condition     = strcontains(local.node_requires, "sts-cert.service") && local.node_environment.STS_TLS_CERT_FILE == "/var/run/sts-tls/certificate.pem"
    error_message = local.node_requires
  }
  assert {
    condition     = contains(keys(azurerm_network_security_rule.rules), "nodes-dns-out")
    error_message = "a public name opens 53 for the ACME check"
  }
}

run "testidpna_zcnc_base" {
  variables {
    environment     = "testidpna"
    cell            = "zcnc"
    cell_phase      = "base"
    public_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).public_hostname
    acme_email      = "tester1@iyasec.io"
    primary_cell    = jsondecode(file("envs/testidpna.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("envs/testidpna.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  assert {
    condition     = azurerm_orchestrated_virtual_machine_scale_set.first.instances == 0 && local.region == "canadacentral" && local.key_kind == "cell"
    error_message = "base: no running node, in the cell's region, under the cell key"
  }
  assert {
    condition     = !contains(keys(local.cell_environment), "STS_GLOBAL_DATABASE_URL") && local.cell_environment.STS_CELL_KEK_VAULT == "https://msvault-abcd.vault.azure.net"
    error_message = "base reads no global state; the cell key names its vault"
  }
  assert {
    condition     = azurerm_lb.intercell[0].frontend_ip_configuration[0].private_ip_address == "10.83.10.5" && azurerm_dns_a_record.public[0].name == "zcnc.na-idp"
    error_message = "the inter-cell address, and the cell's own name"
  }
  assert {
    condition     = jsondecode(local.cell_environment.STS_CELL_PEERS)[0].url == "https://nodes.zwus2.testidpna.mock-sts.internal:8446" && jsondecode(local.cell_environment.STS_CELL_PEERS)[0].consoleUrl == "https://zwus2.na-idp.azure.iyasec.io"
    error_message = local.cell_environment.STS_CELL_PEERS
  }
  assert {
    condition     = jsonencode(sort(keys(local.secrets))) == jsonencode(["cell-kek", "db-app-password", "db-master-password"])
    error_message = "a cell writes only its own secrets"
  }
}

run "testidpna_zwus2_full" {
  variables {
    environment     = "testidpna"
    cell            = "zwus2"
    public_hostname = jsondecode(file("envs/testidpna.cells.tfvars.json")).public_hostname
    acme_email      = "tester1@iyasec.io"
    primary_cell    = jsondecode(file("envs/testidpna.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("envs/testidpna.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  override_data {
    target = data.terraform_remote_state.global
    values = { outputs = {
      writer_host = "mock-sts-testidpna-global-writer-aaaaaa.postgres.database.azure.com"
      read_hosts = {
        zwus2 = "mock-sts-testidpna-global-writer-aaaaaa.postgres.database.azure.com"
        zcnc  = "mock-sts-testidpna-global-zcnc-aaaaaa.postgres.database.azure.com"
      }
      db_port = 5432, db_name = "sts", db_app_user = "sts_app"
    } }
  }
  assert {
    condition     = azurerm_orchestrated_virtual_machine_scale_set.first.instances == 1 && local.is_primary
    error_message = "full, primary"
  }
  assert {
    condition     = contains(keys(local.unit_files["node-a"]), "sts-global-schema.service") && strcontains(local.unit_files["node-a"]["sts-global-schema.service"], "--add-host mock-sts-testidpna-global-writer-aaaaaa.postgres.database.azure.com:10.82.10.12")
    error_message = "the primary's nodes make the global schema, at the writer's endpoint"
  }
  assert {
    condition     = local.cell_environment.STS_GLOBAL_DATABASE_READ_URL == "postgres://sts_app@mock-sts-testidpna-global-writer-aaaaaa.postgres.database.azure.com:5432/sts?sslmode=require"
    error_message = "the primary reads the writer"
  }
  assert {
    condition     = strcontains(local.extra_hosts, "--add-host nodes.zcnc.testidpna.mock-sts.internal:10.83.10.5")
    error_message = local.extra_hosts
  }
}

run "globalidp_zgwc_full" {
  variables {
    environment     = "globalidp"
    cell            = "zgwc"
    public_hostname = jsondecode(file("envs/globalidp.cells.tfvars.json")).public_hostname
    acme_email      = "tester1@iyasec.io"
    primary_cell    = jsondecode(file("envs/globalidp.cells.tfvars.json")).primary_cell
    cells           = jsondecode(file("envs/globalidp.cells.tfvars.json")).cells
    jurisdictions   = jsondecode(file("envs/globalidp.cells.tfvars.json")).jurisdictions
  }
  override_data {
    target = data.terraform_remote_state.global
    values = { outputs = {
      writer_host = "w.postgres.database.azure.com"
      read_hosts  = { zwus2 = "w.postgres.database.azure.com", zgwc = "g.postgres.database.azure.com", zsea = "s.postgres.database.azure.com" }
      db_port     = 5432, db_name = "sts", db_app_user = "sts_app"
    } }
  }
  assert {
    condition     = jsonencode(local.global_hosts) == jsonencode(["--add-host w.postgres.database.azure.com:10.84.10.12", "--add-host g.postgres.database.azure.com:10.85.10.12"])
    error_message = jsonencode(local.global_hosts)
  }
  assert {
    condition     = !contains(keys(local.unit_files["node-a"]), "sts-global-schema.service") && length(jsondecode(local.cell_environment.STS_CELL_PEERS)) == 2
    error_message = "a non-primary cell makes no global schema, and has two peers"
  }
  assert {
    condition     = jsonencode(sort(azurerm_network_security_rule.rules["nodes-intercell-in"].source_address_prefixes)) == jsonencode(["10.84.0.0/16", "10.86.0.0/16"])
    error_message = "8446 from the other two cells"
  }
  assert {
    condition     = jsonencode(sort(azurerm_network_security_rule.rules["private-database-in"].source_address_prefixes)) == jsonencode(["10.84.0.0/24", "10.85.0.0/24", "10.86.0.0/24"])
    error_message = "the global endpoint is dialled by every cell's nodes"
  }
}

run "bad_cell_id_refused" {
  command = plan
  variables {
    environment  = "x1"
    cell         = "zwus2"
    primary_cell = "zwus2"
    cells = {
      zwus2 = { region = "westus2", jurisdiction = "us", vpc_cidr = "10.1.0.0/16" }
      zfoo  = { region = "canadacentral", jurisdiction = "ca", vpc_cidr = "10.2.0.0/16" }
    }
  }
  expect_failures = [var.cells]
}
