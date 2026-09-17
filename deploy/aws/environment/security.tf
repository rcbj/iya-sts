# ---------------------------------------------------------------------------
# THREE SECURITY GROUPS, EACH ACCEPTING ONLY THE ONE BEFORE IT — and a fourth,
# the suite runner's, which accepts only the nodes (below).
#
#   allowed_cidrs ─┐
#   runner's NAT ──┴─443,389,8082─▶ nlb ─8081,389,8082─▶ nodes ─5432─▶ database
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
  nlb_sources = merge(
    { for c in var.allowed_cidrs : c => c },
    var.suite_runner ? { "suite-runner" = "${aws_eip.runner[0].public_ip}/32" } : {},
  )
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

# The nodes call back to the suite runner: a GNAP push to the job's listener
# and the PDP's nudge to the PEP container.
resource "aws_vpc_security_group_egress_rule" "nodes_to_runner" {
  count                        = var.suite_runner ? 1 : 0
  security_group_id            = aws_security_group.nodes.id
  description                  = "Call back to the suite runner (GNAP push, PEP notify)"
  referenced_security_group_id = aws_security_group.runner[0].id
  ip_protocol                  = "tcp"
  from_port                    = 1
  to_port                      = 65535
}

resource "aws_security_group" "runner" {
  count       = var.suite_runner ? 1 : 0
  name        = "${local.prefix}-runner"
  description = "mock-sts ${var.environment}: the suite task, reachable from the nodes only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-runner" }
}

resource "aws_vpc_security_group_ingress_rule" "runner_from_nodes" {
  count                        = var.suite_runner ? 1 : 0
  security_group_id            = aws_security_group.runner[0].id
  description                  = "Callbacks from the nodes (GNAP push, PEP notify)"
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = 1
  to_port                      = 65535
}

# Out through the NAT gateway: the load balancer's public address, ECR, S3,
# CloudWatch Logs and Chrome's own requests.
resource "aws_vpc_security_group_egress_rule" "runner_out" {
  count             = var.suite_runner ? 1 : 0
  security_group_id = aws_security_group.runner[0].id
  description       = "Anything, through the NAT gateway"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
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
