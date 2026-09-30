# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE DEFAULT REALM'S SPIFFE PORTS, PART OF EVERY ENVIRONMENT (#311).
#
#   8092  the SPIFFE Workload API     (spiffe.workloadPort)
#   8181  the SPIRE Server API         (spiffe.serverPort, mutual TLS)
#
# rcbj's decision, 2026-09-28: the default realm's SPIFFE ports are not
# optional and not a separate stack. They were `spiffe-realm/` with
# REALM=default until this date, applied (or not) after the environment —
# and on a build where nobody did, the suite declared SPIFFE unpublished and
# both SPIFFE jobs skipped. `spiffe-realm/` is now for ADDITIONAL realms only,
# and refuses `default`.
#
# **THE NODES ARE REGISTERED BY ADDRESS, BECAUSE ECS MANAGES AT MOST FIVE
# TARGET GROUPS PER SERVICE** and `published_ports` uses all five (https,
# ldap, ldaps, pki, kerberos). So these target groups are not on the services'
# `load_balancer` blocks: this file looks the running nodes up — after every
# service has reached steady state, which `wait_for_steady_state` makes the
# apply wait for — and registers their private addresses. A node restarted
# since the last apply is missing from these two ports until the next one;
# `spiffe-realm/` has always had that property, argued in deploy/aws/CLAUDE.md.
#
# No PROXY protocol here, unlike every other port: SPIFFE's gRPC listeners do
# not read the header. The Workload API port stays unhealthy in product mode,
# which is #166 working (deploy/aws/CLAUDE.md); the SPIRE Server API serves.
# ---------------------------------------------------------------------------
locals {
  spiffe_default_ports = {
    workload = var.spiffe_workload_port
    server   = var.spiffe_server_port
  }
  spiffe_default_ingress = {
    for pair in setproduct(keys(local.spiffe_default_ports), keys(local.nlb_sources)) :
    "${pair[0]}-${pair[1]}" => {
      port = local.spiffe_default_ports[pair[0]]
      cidr = local.nlb_sources[pair[1]]
    }
  }
}

resource "aws_lb_target_group" "spiffe_default" {
  for_each               = local.spiffe_default_ports
  name                   = "${local.prefix}-sp-${each.value}"
  port                   = each.value
  protocol               = "TCP"
  target_type            = "ip"
  vpc_id                 = aws_vpc.main.id
  proxy_protocol_v2      = false
  preserve_client_ip     = "false"
  deregistration_delay   = 30
  connection_termination = true

  health_check {
    protocol            = "TCP"
    port                = "traffic-port"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "spiffe_default" {
  for_each          = local.spiffe_default_ports
  load_balancer_arn = aws_lb.main.arn
  port              = each.value
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.spiffe_default[each.key].arn
  }
}

# The running nodes, once every service is steady: one interface per node,
# each carrying the nodes' security group. The count is the node count, known
# at plan time; the addresses are read at apply.
data "aws_network_interfaces" "nodes" {
  filter {
    name   = "group-id"
    values = [aws_security_group.nodes.id]
  }
  filter {
    name   = "status"
    values = ["in-use"]
  }
  depends_on = [aws_ecs_service.first, aws_ecs_service.others]
}

# ONLY WHILE THE NODES RUN (#311, #98): a cell's `base` phase and a converted
# cell's held `full` phase set every node service to 0, so there is no
# interface to register and indexing an empty list failed the first
# testidpna apply. `spiffe_nodes` is the node count when they run, 0 when
# they are held; the next unheld apply registers them.
locals {
  spiffe_nodes = local.node_desired_count > 0 ? var.node_count : 0
}

data "aws_network_interface" "node" {
  count = local.spiffe_nodes
  id    = sort(data.aws_network_interfaces.nodes.ids)[count.index]
}

resource "aws_lb_target_group_attachment" "spiffe_default" {
  for_each = {
    for pair in setproduct(keys(local.spiffe_default_ports), range(local.spiffe_nodes)) :
    "${pair[0]}-${pair[1]}" => { port = pair[0], node = pair[1] }
  }
  target_group_arn = aws_lb_target_group.spiffe_default[each.value.port].arn
  target_id        = data.aws_network_interface.node[each.value.node].private_ip
  port             = local.spiffe_default_ports[each.value.port]
}

resource "aws_vpc_security_group_ingress_rule" "nlb_spiffe_default" {
  for_each          = local.spiffe_default_ingress
  security_group_id = aws_security_group.nlb.id
  description       = "SPIFFE ${each.key} (default realm) from an allowed address"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_nodes_spiffe_default" {
  for_each                     = local.spiffe_default_ports
  security_group_id            = aws_security_group.nlb.id
  description                  = "SPIFFE ${each.key} (default realm), to the nodes"
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_nlb_spiffe_default" {
  for_each                     = local.spiffe_default_ports
  security_group_id            = aws_security_group.nodes.id
  description                  = "SPIFFE ${each.key} (default realm), from the load balancer"
  referenced_security_group_id = aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
}
