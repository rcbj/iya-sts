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
# INTER-REGION VPC PEERING, A FULL MESH, rather than a transit gateway: n
# cells make n(n-1)/2 peerings — one at two cells, fifteen at globalidp's six
# (#367) — each free to hold and billed only for the bytes that cross it (the same inter-region rate a transit gateway adds
# its own per-attachment hour and per-GB charge on top of). Peering is not
# transitive, which is what a mesh needs and what residency wants: apse1's
# traffic to euc1 never passes through usw2. The quotas are far off: a VPC
# holds fifty active peerings by default, and each of a cell's two route
# tables one route per other cell, under their default of fifty.
#
# HERE, AND NOT IN THE CELLS, because a peering names two VPCs and so exists
# only once both do — which is the reason this stack is applied after every
# cell's first phase. The routes go into the cells' route tables (public:
# the nodes; private: the databases, ../environment/network.tf), and the
# peering's DNS options stay off: the inter-cell name is a Route 53 private
# zone associated with each VPC below, not a resolution of the other VPC's
# private host names.
#
# ONE `for_each` OVER EVERY PAIR (#367, 2026-09-30); it was a module block
# per pair of the four regions #98 named, each with a provider per side. The
# REQUESTER of a pair is whichever of its two cells comes first in the
# order: the primary cell, then the rest by id — so a pair has one peering
# and never two, and adding a cell adds pairs without re-orienting (and so
# replacing) any that exist. Changing `primary_cell` does re-orient the
# primary's pairs, which replaces those peerings; the apply that moves the
# writer is an outage anyway.
# ---------------------------------------------------------------------------
locals {
  cell_order = concat(
    [var.primary_cell],
    sort([for id in keys(var.cells) : id if id != var.primary_cell]),
  )
  pairs = {
    for p in flatten([
      for i, a in local.cell_order : [
        for j, b in local.cell_order : { requester = a, accepter = b } if j > i
      ]
    ]) :
    "${p.requester}_${p.accepter}" => {
      requester = merge(local.cell[p.requester], { id = p.requester })
      accepter  = merge(local.cell[p.accepter], { id = p.accepter })
    }
  }
  peering_common = {
    prefix     = local.prefix
    account_id = local.account_id
  }
}

module "peering" {
  source   = "./modules/peering"
  for_each = local.pairs

  pair   = each.value
  common = local.peering_common
}

# The six per-pair blocks' instances are this one's (testidpna's usw2_cac1
# among them): kept, not replaced, which would cut the inter-cell channel
# and the writes to the global writer for as long as a peering takes.
moved {
  from = module.peering_usw2_cac1[0]
  to   = module.peering["usw2_cac1"]
}

moved {
  from = module.peering_usw2_euc1[0]
  to   = module.peering["usw2_euc1"]
}

moved {
  from = module.peering_usw2_apse1[0]
  to   = module.peering["usw2_apse1"]
}

moved {
  from = module.peering_cac1_euc1[0]
  to   = module.peering["cac1_euc1"]
}

moved {
  from = module.peering_cac1_apse1[0]
  to   = module.peering["cac1_apse1"]
}

moved {
  from = module.peering_euc1_apse1[0]
  to   = module.peering["euc1_apse1"]
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
    for p in setproduct(keys(var.cells), keys(var.cells)) :
    "${p[0]}-in-${p[1]}" => { zone = p[0], vpc = p[1] } if p[0] != p[1]
  }

  zone_id    = local.cell[each.value.zone].intercell_zone_id
  vpc_id     = local.cell[each.value.vpc].vpc_id
  vpc_region = local.cell[each.value.vpc].region
}
