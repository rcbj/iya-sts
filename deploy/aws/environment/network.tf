# ---------------------------------------------------------------------------
# A VPC OF THE ENVIRONMENT'S OWN, THREE AVAILABILITY ZONES.
#
# Public subnets hold the load balancer and the three nodes; private subnets
# hold the two database instances and have no route out of the VPC at all.
#
# NO NAT GATEWAY FOR THE NODES. Each node gets a public IP so it can reach
# ECR, Secrets Manager and CloudWatch Logs, and its security group accepts
# nothing but the load balancer on the published ports. A NAT gateway would
# cost $0.045 an hour plus data processing to buy outbound traffic that leaves
# by a different door.
#
# ONE NAT GATEWAY FOR THE SUITE RUNNER (`suite_runner`, on by default). The
# runner task (runner.tf) sits in a subnet of its own with no public address,
# and reaches the load balancer through the NAT gateway's Elastic IP — a
# FIXED address, which is what lets security.tf admit it to the load balancer
# before the task exists. A Fargate task given a public IP instead would get a
# different address every run, known only after it started.
# ---------------------------------------------------------------------------
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
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.prefix}-public-${local.azs[count.index]}" }
}

resource "aws_subnet" "private" {
  count             = 3
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
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# The private subnets keep the VPC's main route table, which has the local
# route only: nothing in them can reach, or be reached from, the internet.

# ---------------------------------------------------------------------------
# THE SUITE RUNNER'S SUBNET AND ITS WAY OUT.
# ---------------------------------------------------------------------------
resource "aws_subnet" "runner" {
  count             = var.suite_runner ? 1 : 0
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.runner_cidr
  availability_zone = local.azs[0]
  tags              = { Name = "${local.prefix}-runner-${local.azs[0]}" }
}

resource "aws_eip" "runner" {
  count  = var.suite_runner ? 1 : 0
  domain = "vpc"
  tags   = { Name = "${local.prefix}-runner-nat" }
}

resource "aws_nat_gateway" "runner" {
  count         = var.suite_runner ? 1 : 0
  allocation_id = aws_eip.runner[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${local.prefix}-runner-nat" }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "runner" {
  count  = var.suite_runner ? 1 : 0
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-runner-rt" }
}

resource "aws_route" "runner_default" {
  count                  = var.suite_runner ? 1 : 0
  route_table_id         = aws_route_table.runner[0].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.runner[0].id
}

resource "aws_route_table_association" "runner" {
  count          = var.suite_runner ? 1 : 0
  subnet_id      = aws_subnet.runner[0].id
  route_table_id = aws_route_table.runner[0].id
}
