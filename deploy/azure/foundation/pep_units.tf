# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHAT EACH REMOTE PEP ENVIRONMENT IS GIVEN (#1284, ../pep-cluster/).
#
# A PEP environment is an environment of its own, not a unit of an iya-sts
# one: it runs no service node, holds no database and no key-encryption key,
# and reaches the identity service over the internet. So it is not a row of
# `environments` (units.tf gives every unit a KEK, database-key grants and a
# node identity that may read database passwords); it is a row of
# `pep_environments`, and gets only this:
#
#   iya-sts-<env>               the resource group, in home_region, the
#                                deployer's role granted on it
#                                (iam_deployer.tf) and Azure Policy's
#                                *Allowed locations* on it
#   iya-sts-<env>-members       the identity every member VM runs as: reads
#                                the vault's secrets, pulls from the registry,
#                                and — the certificate issuer only, member 1
#                                — answers the ACME challenge and writes the
#                                two certificate objects below
#   iya-sts-<env>-gateway       the identity Application Gateway reads its
#                                listener certificate with
#   mp<env>-<hash>              the Key Vault, for units.tf's reason (a
#                                vault's name is global and soft-deleted):
#     pep-<cluster>-<member>      each member's keys, written by provision.sh,
#                                 read by the member at boot
#     tls                         the ACME bundle (PEM), node-init's cert.sh's
#                                 own format, written by member 1
#     gateway                     a Key Vault CERTIFICATE, the gateway's
#                                 listener: self-signed BY KEY VAULT here, so
#                                 the gateway can be created at all, and then
#                                 replaced by member 1 with the ACME one
#
# WHY A SELF-SIGNED PLACEHOLDER, MADE BY KEY VAULT. Application Gateway reads
# its listener certificate from the vault when it is CREATED, and refuses a
# secret that is not a certificate. The ACME certificate cannot exist yet —
# it is obtained by a member, and the members are built in the same apply.
# Key Vault's own `Self` issuer generates the key INSIDE the vault, so no
# private key is in this or any Terraform state (the resource records the
# public certificate only); member 1 imports the ACME certificate as the next
# version and the gateway, which names the version-less secret, follows it
# within four hours (Microsoft's polling interval). A browser sees the
# placeholder only between the first apply and member 1's first start.
# ---------------------------------------------------------------------------

variable "pep_environments" {
  description = <<-EOT
    EVERY REMOTE PEP ENVIRONMENT THAT MAY BE BUILT (#1284), and its public
    name. Each gets a resource group, two identities and a vault
    (pep_units.tf); one not listed cannot be applied, as with
    `environments`. A name may not also be in `environments`: both would
    claim the resource group `iya-sts-<name>`.
  EOT
  type = map(object({
    public_hostname = string
  }))
  default = {
    testpep = { public_hostname = "test-pep.azure.iyasec.io" }
  }
  validation {
    condition = alltrue([
      for k, v in var.pep_environments : can(regex("^[a-z][a-z0-9]{1,11}$", k))
    ])
    error_message = "A PEP environment's name is 2-12 lower-case letters and digits, starting with a letter."
  }
  validation {
    condition = alltrue([
      for k, v in var.pep_environments : endswith(v.public_hostname, ".${var.dns_zone_name}")
    ])
    error_message = "Every PEP environment's public_hostname must be a name inside dns_zone_name."
  }
}

locals {
  # mp<env>-<4 hex>: ≤ 17 characters, distinct from the units' `ms…` and the
  # regions' `msk…`. The same formula is in ../pep-cluster/main.tf, which
  # finds its vault by name rather than reading this state.
  pep_vault_names = {
    for k, v in var.pep_environments :
    k => "mp${k}-${substr(sha1("${local.subscription_id}/${var.name}/pep/${k}"), 0, 4)}"
  }
}

check "pep_environment_names_are_their_own" {
  assert {
    condition     = length(setintersection(keys(var.pep_environments), keys(var.environments))) == 0
    error_message = "A name is in both environments and pep_environments; both would claim the resource group iya-sts-<name>."
  }
}

resource "azurerm_resource_group" "pep" {
  for_each = var.pep_environments
  name     = "${var.name}-${each.key}"
  location = var.home_region
  tags = merge(local.common_tags, {
    Environment = each.key
    Cell        = ""
    Role        = "remote-pep-cluster"
  })
}

resource "azurerm_resource_group_policy_assignment" "pep_locations" {
  for_each             = var.pep_environments
  name                 = "${var.name}-${each.key}-locations"
  resource_group_id    = azurerm_resource_group.pep[each.key].id
  policy_definition_id = data.azurerm_policy_definition.allowed_locations.id
  description          = "iya-sts (#1284): the region fence"
  parameters = jsonencode({
    listOfAllowedLocations = { value = [var.home_region] }
  })
}

resource "azurerm_user_assigned_identity" "pep_members" {
  for_each            = var.pep_environments
  name                = "${var.name}-${each.key}-members"
  location            = var.home_region
  resource_group_name = azurerm_resource_group.pep[each.key].name
  tags                = azurerm_resource_group.pep[each.key].tags
}

resource "azurerm_user_assigned_identity" "pep_gateway" {
  for_each            = var.pep_environments
  name                = "${var.name}-${each.key}-gateway"
  location            = var.home_region
  resource_group_name = azurerm_resource_group.pep[each.key].name
  tags                = azurerm_resource_group.pep[each.key].tags
}

resource "azurerm_key_vault" "pep" {
  for_each            = var.pep_environments
  name                = local.pep_vault_names[each.key]
  location            = var.home_region
  resource_group_name = azurerm_resource_group.pep[each.key].name
  tenant_id           = local.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true
  # units.tf's argument: the members' secrets are written and removed by
  # provision.sh; purge protection would only keep a removed key readable.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  public_network_access_enabled = true

  tags = azurerm_resource_group.pep[each.key].tags
}

# The administrator makes the two placeholders below.
resource "azurerm_role_assignment" "admin_pep_vault_secrets" {
  for_each             = var.pep_environments
  scope                = azurerm_key_vault.pep[each.key].id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "admin_pep_vault_certificates" {
  for_each             = var.pep_environments
  scope                = azurerm_key_vault.pep[each.key].id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "time_sleep" "pep_vault_rbac" {
  depends_on = [
    azurerm_role_assignment.admin_pep_vault_secrets,
    azurerm_role_assignment.admin_pep_vault_certificates,
  ]
  create_duration = "90s"
}

# node-init's cert.sh's bundle, `not-issued` until member 1 fills it (units.tf
# `tls`, the same contract).
resource "azurerm_key_vault_secret" "pep_tls" {
  for_each     = var.pep_environments
  name         = "tls"
  key_vault_id = azurerm_key_vault.pep[each.key].id
  value        = "not-issued"
  content_type = "application/x-pem-file"
  tags = {
    public-hostname = each.value.public_hostname
  }

  lifecycle {
    ignore_changes = [value, content_type, tags, expiration_date, not_before_date]
  }

  depends_on = [time_sleep.pep_vault_rbac]
}

# THE GATEWAY'S LISTENER CERTIFICATE, SELF-SIGNED BY KEY VAULT (the header).
# Exportable, because Application Gateway reads the certificate WITH its key
# through the vault's secret endpoint; the key is still Key Vault's, made
# there, and in no state. Every later version is member 1's ACME import, so
# nothing here is compared again.
resource "azurerm_key_vault_certificate" "pep_gateway" {
  for_each     = var.pep_environments
  name         = "gateway"
  key_vault_id = azurerm_key_vault.pep[each.key].id

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }
    key_properties {
      exportable = true
      key_type   = "RSA"
      key_size   = 2048
      reuse_key  = false
    }
    secret_properties {
      content_type = "application/x-pkcs12"
    }
    x509_certificate_properties {
      subject            = "CN=${each.value.public_hostname}"
      validity_in_months = 3
      key_usage          = ["digitalSignature", "keyEncipherment"]
      extended_key_usage = ["1.3.6.1.5.5.7.3.1"]
      subject_alternative_names {
        dns_names = [each.value.public_hostname]
      }
    }
  }

  lifecycle {
    ignore_changes = all
  }

  depends_on = [time_sleep.pep_vault_rbac]
}

# --- What a member may do -----------------------------------------------------

resource "azurerm_role_assignment" "pep_members_read_vault" {
  for_each             = var.pep_environments
  scope                = azurerm_key_vault.pep[each.key].id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.pep_members[each.key].principal_id
}

resource "azurerm_role_assignment" "pep_members_pull" {
  for_each             = var.pep_environments
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.pep_members[each.key].principal_id
}

# THE CERTIFICATE ISSUER'S RIGHTS, scoped to the objects, not the vault:
# a new version of the `tls` bundle (node-init's cert.sh), an import of the
# `gateway` certificate (../pep-cluster/units/pep-gateway-cert.sh.tftpl), and
# the zone's TXT records (units.tf's narrow custom role). Every member holds
# the one identity, so every member could; only member 1 is configured to.
resource "azurerm_role_assignment" "pep_members_write_tls" {
  for_each             = var.pep_environments
  scope                = azurerm_key_vault_secret.pep_tls[each.key].resource_versionless_id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_user_assigned_identity.pep_members[each.key].principal_id
}

resource "azurerm_role_assignment" "pep_members_import_gateway" {
  for_each             = var.pep_environments
  scope                = azurerm_key_vault_certificate.pep_gateway[each.key].resource_manager_versionless_id
  role_definition_name = "Key Vault Certificates Officer"
  principal_id         = azurerm_user_assigned_identity.pep_members[each.key].principal_id
}

resource "azurerm_role_assignment" "pep_members_acme" {
  for_each           = var.pep_environments
  scope              = azurerm_dns_zone.public.id
  role_definition_id = azurerm_role_definition.acme_txt.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.pep_members[each.key].principal_id
}

# --- What the gateway may do --------------------------------------------------
# Read its certificate, through the secret endpoint, and nothing else.
resource "azurerm_role_assignment" "pep_gateway_read_vault" {
  for_each             = var.pep_environments
  scope                = azurerm_key_vault.pep[each.key].id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.pep_gateway[each.key].principal_id
}
