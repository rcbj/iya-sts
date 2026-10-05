# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
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
  cidr_block           = local.vpc_cidr
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
# A CELL'S PRIVATE SUBNETS GET A ROUTE TABLE OF THEIR OWN (#98, 2026-09-28).
#
# In a cell the private subnets hold more than this cell's database: the
# global database's writer (in the primary cell) or its read replica (in each
# other) is placed in them too (global_db.tf), and the writer answers nodes in
# OTHER cells, across the peering. Its replies need a route back to those
# cells' CIDRs, and the global/ stack adds one per peer — to a table it can
# find by id and that carries the project's tag. The VPC's MAIN route table
# is neither: AWS makes it untagged, and the deployer may add a route only to
# a table tagged Project = STS (foundation/iam_deployer.tf). So a cell's
# private subnets are associated with this table, which has the local route
# and nothing else until the peering adds the peers — still no route to the
# internet.
#
# A single-cell environment keeps the main table, as it always has.
# ---------------------------------------------------------------------------
resource "aws_route_table" "private" {
  count  = local.multi ? 1 : 0
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = local.multi ? 3 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}
