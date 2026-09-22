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
# NO NAT GATEWAY AT ALL SINCE 2026-09-21. There was one for the in-VPC suite
# runner (`runner.tf`, `suite_runner`), removed that day: the suite runs from
# deploy/aws/run-suite.sh against the load balancer, and the two jobs that
# need the nodes to call them back run in `suite-callbacks/`, a per-run stack
# with a subnet and NAT gateway of its own that is destroyed after the run.
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

