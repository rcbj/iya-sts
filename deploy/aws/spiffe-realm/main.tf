# ---------------------------------------------------------------------------
# A TRUST REALM'S TWO SPIFFE PORTS, PUBLISHED ON THE ENVIRONMENT'S NLB
# (2026-09-18) — the Workload API and the SPIRE Server API, each on the same
# number outside and inside, as `environment/locals.tf`'s `ldap` row is.
#
# A REALM IS TOLD APART BY ITS ADDRESS, AND ON FARGATE THAT MEANS ITS PORTS.
# spiffe/CLAUDE.md's design gives each realm an address of its own and keeps
# 8092 / 8181, because gRPC has no path to put a realm in. A Fargate task has
# ONE address, so here every realm binds `0.0.0.0` on ports of its own — which
# the service allows (`spiffe_server.ts`'s `claimedBy()` compares host AND
# port) — and the load balancer publishes those ports. The default realm keeps
# 8092 / 8181, and a realm may not take them.
#
# THE NODES ARE REGISTERED BY ADDRESS, BY THIS STACK, AND THAT IS THE COST.
# Every other port the load balancer carries is a target group ECS keeps up to
# date, through a `load_balancer` block on each node's service
# (environment/ecs.tf). ECS allows FIVE per service, and `testidp` uses all
# five (https, ldap, ldaps, pki, kerberos) — so these target groups are not
# ECS's, and the nodes' current private addresses are looked up here and
# registered. A task that restarts comes back on a NEW address: its old one
# goes unhealthy and its new one is registered nowhere until this stack is
# applied again. RE-APPLY AFTER ANY DEPLOY OR TASK RESTART. rcbj chose this
# over a Lambda that follows ECS's task events (which the deployer role has no
# permission to create) on 2026-09-18.
#
# NO PROXY PROTOCOL. The environment's target groups send a PROXY v2 header
# and the node reads it (common/proxy_protocol.ts) — on the main port, LDAP,
# LDAPS and the KDC. SPIFFE's gRPC listeners do NOT read it, and a header in
# front of a gRPC or TLS stream is a broken connection, so these target groups
# have it off. The node therefore sees the load balancer's address as the
# caller, which is what a Workload API `peer:` selector will record.
#
# NOTHING HERE TURNS THE REALM'S SPIFFE ON. A realm is created with it off and
# both ports 0 (common/realms.js, SEEDED_FOR_REALM); the realm has to be given
# `spiffe.enabled`, `spiffe.workloadPort` and `spiffe.serverPort` — the SAME
# two numbers as this stack's — in the console or through /admin-api. Until it
# is, the target groups report every node unhealthy and the ports refuse.
# ---------------------------------------------------------------------------

locals {
  prefix     = "${var.name}-${var.environment}"
  is_default = var.realm == "default"

  # The two ports, by name. Same number on both sides.
  spiffe_ports = {
    workload = var.workload_port
    server   = var.server_port
  }

  # PORTS A REALM MAY NOT TAKE: every node port and load-balancer port the
  # environment already uses (environment/locals.tf's `published_ports`, with
  # testidp's 80 for the PKI listener and 88 for the KDC), the embedded
  # debugger's listener, and — for any realm but the default one — the default
  # realm's own 8092 and 8181, which it binds on 0.0.0.0 at startup whether or
  # not its SPIFFE is on. Written out rather than read from the environment's
  # state because a listener port is not one of its outputs.
  reserved_ports = concat(
    [80, 88, 389, 443, 636, 8081, 8082, 8444],
    local.is_default ? [] : [8092, 8181],
  )
  port_problem = (
    var.workload_port == var.server_port
    ? "workload_port and server_port are both ${var.workload_port}; a realm needs two ports."
    : length(setintersection(toset(values(local.spiffe_ports)), toset(local.reserved_ports))) > 0
    ? "one of ${var.workload_port} and ${var.server_port} is already used by this environment or by the default realm (${join(", ", local.reserved_ports)})."
    : ""
  )

  public_host = (
    data.terraform_remote_state.environment.outputs.public_hostname != ""
    ? data.terraform_remote_state.environment.outputs.public_hostname
    : data.aws_lb.main.dns_name
  )
}

# --- What the environment stack built, found by name -----------------------

# Only for the public name clients are given (outputs.tf); everything this
# stack changes is looked up directly, so it never depends on an output the
# environment might rename.
data "terraform_remote_state" "environment" {
  backend = "s3"
  config = {
    region = var.aws_region
    bucket = "${var.name}-terraform-state-${data.aws_caller_identity.current.account_id}"
    key    = "environment/${var.environment}.tfstate"
  }
}

data "aws_lb" "main" {
  name = local.prefix
}

data "aws_security_group" "nlb" {
  name   = "${local.prefix}-nlb"
  vpc_id = data.aws_lb.main.vpc_id
}

data "aws_security_group" "nodes" {
  name   = "${local.prefix}-nodes"
  vpc_id = data.aws_lb.main.vpc_id
}

# THE NODES' CURRENT ADDRESSES: every network interface in use that carries
# the nodes' security group. Only the nodes' tasks carry it — the suite runner
# has a group of its own — so this is one interface per running node, and a
# task mid-replacement can briefly add a second.
data "aws_network_interfaces" "nodes" {
  filter {
    name   = "group-id"
    values = [data.aws_security_group.nodes.id]
  }
  filter {
    name   = "status"
    values = ["in-use"]
  }
}

data "aws_network_interface" "node" {
  for_each = toset(data.aws_network_interfaces.nodes.ids)
  id       = each.value
}

# WHO MAY CONNECT: whoever the environment admits on 443, copied from the load
# balancer's own rules — `allowed_cidrs` and, where there is one, the suite
# runner's NAT address. So these ports are exactly as open as the main port,
# and there is no second list of addresses to keep in step. A changed
# `allowed_ip` on the environment reaches these ports at this stack's next
# apply.
data "aws_vpc_security_group_rules" "nlb" {
  filter {
    name   = "group-id"
    values = [data.aws_security_group.nlb.id]
  }
}

data "aws_vpc_security_group_rule" "nlb" {
  for_each               = toset(data.aws_vpc_security_group_rules.nlb.ids)
  security_group_rule_id = each.value
}

locals {
  allowed_cidrs = toset([
    for r in data.aws_vpc_security_group_rule.nlb : r.cidr_ipv4
    if !r.is_egress && r.from_port == 443 && r.cidr_ipv4 != null && r.cidr_ipv4 != ""
  ])

  node_ips = toset([for n in data.aws_network_interface.node : n.private_ip])

  # One registration per (port, node address).
  attachments = {
    for pair in setproduct(keys(local.spiffe_ports), local.node_ips) :
    "${pair[0]}-${pair[1]}" => { port = pair[0], ip = pair[1] }
  }

  # One load-balancer ingress rule per (port, allowed address).
  ingress = {
    for pair in setproduct(keys(local.spiffe_ports), local.allowed_cidrs) :
    "${pair[0]}-${pair[1]}" => { port = local.spiffe_ports[pair[0]], cidr = pair[1] }
  }
}

# --- The load balancer ------------------------------------------------------

resource "aws_lb_target_group" "spiffe" {
  for_each = local.spiffe_ports

  # `mock-sts-<env>-sp-<port>`: at most 30 characters with a 12-character
  # environment name, under ELB's 32, and inside the deployer's `mock-sts-*`
  # scope. Named by PORT rather than realm because a realm id can be 31
  # characters and a port is unique in an environment anyway — the Realm tag
  # says whose it is.
  name                   = "${local.prefix}-sp-${each.value}"
  port                   = each.value
  protocol               = "TCP"
  target_type            = "ip"
  vpc_id                 = data.aws_lb.main.vpc_id
  proxy_protocol_v2      = false
  preserve_client_ip     = "false"
  deregistration_delay   = 30
  connection_termination = true

  # A TCP connect. A gRPC server accepts one and closes it when nothing is
  # sent, so this is "is the realm's listener bound on that node".
  health_check {
    protocol            = "TCP"
    port                = "traffic-port"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  lifecycle {
    precondition {
      condition     = local.port_problem == ""
      error_message = local.port_problem
    }
    precondition {
      condition     = length(local.node_ips) > 0
      error_message = "No running node was found (no in-use interface carries ${local.prefix}-nodes). Apply the environment first, and wait for its services to reach steady state."
    }
  }
}

resource "aws_lb_target_group_attachment" "nodes" {
  for_each = local.attachments

  target_group_arn = aws_lb_target_group.spiffe[each.value.port].arn
  target_id        = each.value.ip
  port             = local.spiffe_ports[each.value.port]
}

resource "aws_lb_listener" "spiffe" {
  for_each = local.spiffe_ports

  load_balancer_arn = data.aws_lb.main.arn
  port              = each.value
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.spiffe[each.key].arn
  }
}

# --- The security groups ----------------------------------------------------
# The same three rules per port environment/security.tf writes for each of its
# own: the world (as far as it is allowed) to the load balancer, the load
# balancer to the nodes, and the nodes accepting the load balancer. Separate
# rule resources, so this stack's rules are added and removed without touching
# the groups or the environment's rules in them.

resource "aws_vpc_security_group_ingress_rule" "nlb_spiffe" {
  for_each          = local.ingress
  security_group_id = data.aws_security_group.nlb.id
  description       = "SPIFFE ${each.key} for realm ${var.realm}"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_nodes_spiffe" {
  for_each                     = local.spiffe_ports
  security_group_id            = data.aws_security_group.nlb.id
  description                  = "SPIFFE ${each.key} for realm ${var.realm}, to the nodes"
  referenced_security_group_id = data.aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_nlb_spiffe" {
  for_each                     = local.spiffe_ports
  security_group_id            = data.aws_security_group.nodes.id
  description                  = "SPIFFE ${each.key} for realm ${var.realm}, from the load balancer"
  referenced_security_group_id = data.aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
}
