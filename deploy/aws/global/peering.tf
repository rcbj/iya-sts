# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE INTER-CELL NETWORK: EVERY PAIR OF CELL VPCs PEERED, AND EVERY CELL'S
# PRIVATE NAME RESOLVABLE IN EVERY OTHER (issue #98, 2026-09-28).
#
# WHAT CROSSES IT: the inter-cell channel on 8446 (../environment/intercell.tf)
# and each cell's writes to the global database's writer in the primary
# cell. RDS's own replication does not; it is carried by RDS.
#
# INTER-REGION VPC PEERING, A FULL MESH, rather than a transit gateway: two to
# four cells make one to six peerings, each free to hold and billed only for
# the bytes that cross it (the same inter-region rate a transit gateway adds
# its own per-attachment hour and per-GB charge on top of). Peering is not
# transitive, which is what a mesh needs and what residency wants: cac1's
# traffic to euc1 never passes through usw2.
#
# HERE, AND NOT IN THE CELLS, because a peering names two VPCs and so exists
# only once both do — which is the reason this stack is applied after every
# cell's first phase. The routes go into the cells' route tables (public:
# the nodes; private: the databases, ../environment/network.tf), and the
# peering's DNS options stay off: the inter-cell name is a Route 53 private
# zone associated with each VPC below, not a resolution of the other VPC's
# private host names.
#
# A BLOCK PER PAIR, SIX FOR THE FOUR REGIONS the design names, each present
# only when both its cells are (providers.tf says why they are written out).
# The requester is the pair's first cell in the fixed order usw2, cac1, euc1,
# apse1, so a pair has one peering and never two.
# ---------------------------------------------------------------------------
locals {
  # A pair's two cells, or null when either is not in this environment.
  pair = {
    for p in [
      ["usw2", "cac1"], ["usw2", "euc1"], ["usw2", "apse1"],
      ["cac1", "euc1"], ["cac1", "apse1"], ["euc1", "apse1"],
    ] :
    "${p[0]}_${p[1]}" => (contains(keys(local.aws_cells), p[0]) && contains(keys(local.aws_cells), p[1])) ? {
      requester = merge(local.cell[p[0]], { id = p[0] })
      accepter  = merge(local.cell[p[1]], { id = p[1] })
    } : null
  }
  peering_common = {
    prefix     = local.prefix
    account_id = local.account_id
  }
}

module "peering_usw2_cac1" {
  source    = "./modules/peering"
  count     = local.pair["usw2_cac1"] != null ? 1 : 0
  providers = { aws.requester = aws.usw2, aws.accepter = aws.cac1 }
  pair      = local.pair["usw2_cac1"]
  common    = local.peering_common
}

module "peering_usw2_euc1" {
  source    = "./modules/peering"
  count     = local.pair["usw2_euc1"] != null ? 1 : 0
  providers = { aws.requester = aws.usw2, aws.accepter = aws.euc1 }
  pair      = local.pair["usw2_euc1"]
  common    = local.peering_common
}

module "peering_usw2_apse1" {
  source    = "./modules/peering"
  count     = local.pair["usw2_apse1"] != null ? 1 : 0
  providers = { aws.requester = aws.usw2, aws.accepter = aws.apse1 }
  pair      = local.pair["usw2_apse1"]
  common    = local.peering_common
}

module "peering_cac1_euc1" {
  source    = "./modules/peering"
  count     = local.pair["cac1_euc1"] != null ? 1 : 0
  providers = { aws.requester = aws.cac1, aws.accepter = aws.euc1 }
  pair      = local.pair["cac1_euc1"]
  common    = local.peering_common
}

module "peering_cac1_apse1" {
  source    = "./modules/peering"
  count     = local.pair["cac1_apse1"] != null ? 1 : 0
  providers = { aws.requester = aws.cac1, aws.accepter = aws.apse1 }
  pair      = local.pair["cac1_apse1"]
  common    = local.peering_common
}

module "peering_euc1_apse1" {
  source    = "./modules/peering"
  count     = local.pair["euc1_apse1"] != null ? 1 : 0
  providers = { aws.requester = aws.euc1, aws.accepter = aws.apse1 }
  pair      = local.pair["euc1_apse1"]
  common    = local.peering_common
}

# ---------------------------------------------------------------------------
# EACH CELL'S INTER-CELL NAME, RESOLVABLE IN EVERY OTHER CELL'S VPC.
#
# A cell's `nodes.<cell>.<env>.mock-sts.internal` lives in a Route 53 PRIVATE
# zone that Cloud Map made and associated with that cell's VPC
# (../environment/intercell.tf). Associating it with each other cell's VPC —
# across regions, which private zones allow — is what lets a peer's nodes
# resolve it, through their own VPC's resolver, with no resolver endpoint and
# no public record. Route 53 is global, so the default provider makes every
# association; the VPC's region is named on each.
# ---------------------------------------------------------------------------
resource "aws_route53_zone_association" "intercell" {
  for_each = {
    for p in setproduct(keys(local.aws_cells), keys(local.aws_cells)) :
    "${p[0]}-in-${p[1]}" => { zone = p[0], vpc = p[1] } if p[0] != p[1]
  }

  zone_id    = local.cell[each.value.zone].intercell_zone_id
  vpc_id     = local.cell[each.value.vpc].vpc_id
  vpc_region = local.cell[each.value.vpc].region
}
