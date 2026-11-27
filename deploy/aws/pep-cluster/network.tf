# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE PEP ENVIRONMENT'S OWN NETWORK. A VPC peered with nothing, in two zones
# (an ALB needs two): public subnets for the load balancer and the NAT
# gateway, private subnets for the members.
#
# ONE NAT GATEWAY, NOT ONE PER ZONE. It is the environment's single egress
# address (`egress_ip`), the one the identity service admits — a second
# would be a second address to admit and a second hourly charge, for a test
# environment that loses only its pulls (not its decisions: a member keeps
# enforcing what it last pulled) while one zone is down.
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "zone-type"
    values = ["availability-zone"]
  }
}

locals {
  azs           = slice(sort(data.aws_availability_zones.available.names), 0, 2)
  public_cidrs  = [for i in range(2) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_cidrs = [for i in range(2) : cidrsubnet(var.vpc_cidr, 8, 10 + i)]
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.public_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.prefix}-public-${local.azs[count.index]}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = local.azs[count.index]
  tags              = { Name = "${local.prefix}-private-${local.azs[count.index]}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-public-rt" }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${local.prefix}-nat" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${local.prefix}-nat" }
  depends_on    = [aws_internet_gateway.main]
}

# A table of its own, tagged (the deployer may add a route only to a table
# carrying the project's tag; the VPC's main table carries none).
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-private-rt" }
}

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# --- Security groups --------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${local.prefix}-alb"
  description = "iya-sts ${var.environment}: PEP cluster load balancer, open to allowed_cidrs"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "pep" {
  name        = "${local.prefix}-pep"
  description = "iya-sts ${var.environment}: PEP cluster members, reachable from the load balancer only"
  vpc_id      = aws_vpc.main.id
}

locals {
  # Every (port, source) pair the load balancer admits: its client listeners
  # from allowed_cidrs (80 only to be redirected), each notify port from
  # notify_cidrs. The WAF holds the same allowlist; the group is the floor.
  client_ports = concat([80, 443], var.publish_decision_api ? [var.decision_port] : [])
  alb_ingress = merge(
    { for pair in setproduct(local.client_ports, var.allowed_cidrs) :
      "${pair[0]}-${pair[1]}" => { port = pair[0], cidr = pair[1] }
    },
    { for pair in setproduct(values(local.notify_ports), var.notify_cidrs) :
      "${pair[0]}-${pair[1]}" => { port = pair[0], cidr = pair[1] }
    },
  )
}

resource "aws_vpc_security_group_ingress_rule" "alb" {
  for_each          = local.alb_ingress
  security_group_id = aws_security_group.alb.id
  description       = "Port ${each.value.port} from ${each.value.cidr}"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

resource "aws_vpc_security_group_egress_rule" "alb_to_pep" {
  for_each                     = toset([tostring(local.pep_https_port), tostring(local.pep_proxy_port)])
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward and health-check to the members on ${each.value}"
  referenced_security_group_id = aws_security_group.pep.id
  ip_protocol                  = "tcp"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
}

resource "aws_vpc_security_group_ingress_rule" "pep_from_alb" {
  for_each                     = toset([tostring(local.pep_https_port), tostring(local.pep_proxy_port)])
  security_group_id            = aws_security_group.pep.id
  description                  = "The load balancer on ${each.value}"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = tonumber(each.value)
  to_port                      = tonumber(each.value)
}

# ECR, Secrets Manager, CloudWatch Logs and the identity service, all on 443,
# through the NAT gateway.
resource "aws_vpc_security_group_egress_rule" "pep_https" {
  security_group_id = aws_security_group.pep.id
  description       = "AWS APIs and the identity service, on 443"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}
