# ---------------------------------------------------------------------------
# THREE SECURITY GROUPS, EACH ACCEPTING ONLY THE ONE BEFORE IT.
#
#   allowed_cidrs ──443──▶ nlb ──8081──▶ nodes ──5432──▶ database
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

resource "aws_vpc_security_group_ingress_rule" "nlb_https" {
  for_each          = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.nlb.id
  description       = "HTTPS from an allowed address"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_nodes" {
  security_group_id            = aws_security_group.nlb.id
  description                  = "Forward and health-check to the nodes"
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = local.container_port
  to_port                      = local.container_port
}

resource "aws_security_group" "nodes" {
  name        = "${local.prefix}-nodes"
  description = "mock-sts ${var.environment}: the nodes, reachable from the load balancer only"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-nodes" }
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_nlb" {
  security_group_id            = aws_security_group.nodes.id
  description                  = "The load balancer, with PROXY protocol v2"
  referenced_security_group_id = aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = local.container_port
  to_port                      = local.container_port
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
