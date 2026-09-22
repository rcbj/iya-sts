# ---------------------------------------------------------------------------
# THREE SECURITY GROUPS, EACH ACCEPTING ONLY THE ONE BEFORE IT — and a fourth,
# the suite runner's, which accepts only the nodes (below).
#
#   allowed_cidrs ─┐
#   runner's NAT ──┴─443,389,636,pki─▶ nlb ─8081,389,636,8082─▶ nodes ─5432─▶ db
#
# `pki` is the plain-HTTP CRL/OCSP front-end port — 8082 in the test
# environments and 80 in `testidp` (locals.tf, `var.pki_listener_port`) —
# and the node behind it is on 8082 either way. 636 (LDAPS) joined the list
# on 2026-09-17, and TCP 88 (the KDC) in `testidp` on 2026-09-18
# (`var.publish_kerberos`; no UDP). Every rule below iterates
# `published_ports`, so neither side is written here.
#                                                                   │
#   runner ◀──────────── any TCP (GNAP push, the PEP's notify) ─────┘
#
# The suite runner (runner.tf) reaches the load balancer the way any client
# does, from the NAT gateway's public address, which is why that address is
# in the load balancer's list beside allowed_cidrs. The nodes reach the runner
# directly: a GNAP push goes to a listener the job opens on an ephemeral port,
# and the PDP nudges the PEP container on 9090.
#
# Rules are separate `aws_vpc_security_group_*_rule` resources rather than
# inline blocks, so a change to one address replaces one rule and not the
# group — the pattern the parent project's krb5 stack uses for the same reason.
# ---------------------------------------------------------------------------
resource "aws_security_group" "nlb" {
  name        = "${local.prefix}-nlb"
  description = "mock-sts ${var.environment}: the load balancer, open to allowed_cidrs on 443"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-nlb" }
}

locals {
  # Every (published port, allowed source) pair: allowed_cidrs, and the suite
  # runner's NAT address when there is a runner. Keyed by a name known at plan
  # time: the NAT address is not, and a `for_each` key may not wait for an
  # apply. (The group's description still says 443: a description change
  # replaces a security group.)
  # (The suite runner's NAT address was a second source until 2026-09-21,
  # when the in-VPC runner was removed: the suite runs from
  # deploy/aws/run-suite.sh, from an address in `allowed_cidrs`.)
  nlb_sources = { for c in var.allowed_cidrs : c => c }
  nlb_ingress = {
    for pair in setproduct(keys(local.published_ports), keys(local.nlb_sources)) :
    "${pair[0]}-${pair[1]}" => {
      port = local.published_ports[pair[0]].listener
      cidr = local.nlb_sources[pair[1]]
    }
  }
}

resource "aws_vpc_security_group_ingress_rule" "nlb_ports" {
  for_each          = local.nlb_ingress
  security_group_id = aws_security_group.nlb.id
  description       = "Port ${each.value.port} from an allowed address"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_nodes" {
  for_each                     = local.published_ports
  security_group_id            = aws_security_group.nlb.id
  description                  = "Forward and health-check to the nodes on ${each.value.container}"
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = each.value.container
  to_port                      = each.value.container
}

resource "aws_security_group" "nodes" {
  name        = "${local.prefix}-nodes"
  description = "mock-sts ${var.environment}: the nodes, reachable from the load balancer only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-nodes" }
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_nlb" {
  for_each                     = local.published_ports
  security_group_id            = aws_security_group.nodes.id
  description                  = "The load balancer on ${each.value.container}, with PROXY protocol v2"
  referenced_security_group_id = aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = each.value.container
  to_port                      = each.value.container
}

# Outbound: the database, and HTTPS to ECR, Secrets Manager and CloudWatch.
# Open to everywhere on 443 because those service endpoints are public
# addresses with no stable list.
resource "aws_vpc_security_group_egress_rule" "nodes_https" {
  security_group_id = aws_security_group.nodes.id
  description       = "AWS APIs: ECR, Secrets Manager, CloudWatch Logs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "nodes_to_database" {
  security_group_id            = aws_security_group.nodes.id
  description                  = "PostgreSQL over TLS"
  referenced_security_group_id = aws_security_group.database.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

resource "aws_security_group" "database" {
  name        = "${local.prefix}-database"
  description = "mock-sts ${var.environment}: RDS, reachable from the nodes only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-database" }
}

resource "aws_vpc_security_group_ingress_rule" "database_from_nodes" {
  security_group_id            = aws_security_group.database.id
  description                  = "PostgreSQL from the nodes"
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
}

moved {
  from = aws_vpc_security_group_egress_rule.nlb_to_nodes
  to   = aws_vpc_security_group_egress_rule.nlb_to_nodes["https"]
}

moved {
  from = aws_vpc_security_group_ingress_rule.nodes_from_nlb
  to   = aws_vpc_security_group_ingress_rule.nodes_from_nlb["https"]
}
