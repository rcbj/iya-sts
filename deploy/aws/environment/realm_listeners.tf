# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A TRUST REALM'S OWN LOAD BALANCER (#99, 2026-10-02).
#
# A realm may have a front-end listener of its own: since #472 a definition
# in the realm's `listeners.realm`, which the service binds on every node
# (tls/listeners.js), and a `listeners.applications` entry mapping `*` to it,
# which builds every URL of the realm on its `publicBaseUrl`. The load
# balancer and the
# DNS name in front of it are the DEPLOYMENT'S, and this file makes them, one
# realm per entry of `var.realm_listeners`:
#
#   * a network load balancer of the realm's OWN, internet-facing, in the
#     public subnets, under the same security group as the main one — so a
#     realm can be moved, filtered or torn down without touching the others;
#   * a TCP listener on 443 forwarding, TLS passed through, to the realm's port
#     on the nodes, with PROXY protocol v2 (the realm listener reads it as the
#     main port does) and an HTTPS health check under the realm's own prefix
#     (`/realm/<id>/healthcheck`: a realm's listener answers its own paths
#     only);
#   * the security-group rules from the load balancer to the nodes on that
#     port;
#   * optionally a CNAME for the realm's host name in a Route 53 zone.
#
# **THE NODES ARE REGISTERED BY ADDRESS, AS spiffe_default.tf DOES**, because
# ECS manages at most five target groups per service and `published_ports`
# uses them (https, ldap, ldaps, pki, kerberos). A node restarted since the
# last apply is missing from a realm's load balancer until the next apply —
# the same property, argued in deploy/aws/CLAUDE.md. A realm with a high
# availability need wants a registration that follows the tasks (an
# EventBridge rule on ECS task state, or Cloud Map); that is a follow-up.
#
# **THE SERVICE IS NOT TOLD BY THIS FILE.** A realm's listener settings live
# in the realm, in the database, set through /admin-api (or the console); the
# `realm_listener_settings` output prints the two calls that match this
# file's entries, for the operator to run once the environment is up.
# ---------------------------------------------------------------------------

locals {
  realm_listeners = { for r in var.realm_listeners : r.realm => r }
  # Load balancer and target group names are 32 characters at most; a realm id
  # can be long, so the name carries a digest of it.
  realm_listener_names = {
    for id, r in local.realm_listeners :
    id => "${substr(local.prefix, 0, 20)}-rl-${substr(md5(id), 0, 6)}"
  }
  realm_listener_nodes = local.node_desired_count > 0 ? var.node_count : 0
}

resource "aws_lb" "realm" {
  for_each                         = local.realm_listeners
  name                             = local.realm_listener_names[each.key]
  load_balancer_type               = "network"
  internal                         = false
  subnets                          = aws_subnet.public[*].id
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = false
  tags = {
    Realm = each.key
  }
}

resource "aws_lb_target_group" "realm" {
  for_each               = local.realm_listeners
  name                   = local.realm_listener_names[each.key]
  port                   = each.value.port
  protocol               = "TCP"
  target_type            = "ip"
  vpc_id                 = aws_vpc.main.id
  proxy_protocol_v2      = true
  preserve_client_ip     = "false"
  deregistration_delay   = 30
  connection_termination = true

  health_check {
    protocol            = "HTTPS"
    port                = "traffic-port"
    path                = "/${var.realm_path_segment}/${each.key}/healthcheck"
    matcher             = "200"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "realm" {
  for_each          = local.realm_listeners
  load_balancer_arn = aws_lb.realm[each.key].arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.realm[each.key].arn
  }
}

resource "aws_lb_target_group_attachment" "realm" {
  for_each = {
    for pair in setproduct(keys(local.realm_listeners), range(local.realm_listener_nodes)) :
    "${pair[0]}-${pair[1]}" => { realm = pair[0], node = pair[1] }
  }
  target_group_arn = aws_lb_target_group.realm[each.value.realm].arn
  target_id        = data.aws_network_interface.node[each.value.node].private_ip
  port             = local.realm_listeners[each.value.realm].port
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_nodes_realm" {
  for_each                     = local.realm_listeners
  security_group_id            = aws_security_group.nlb.id
  description                  = "Realm ${each.key}'s own listener, to the nodes"
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_nlb_realm" {
  for_each                     = local.realm_listeners
  security_group_id            = aws_security_group.nodes.id
  description                  = "Realm ${each.key}'s own listener, from its load balancer"
  referenced_security_group_id = aws_security_group.nlb.id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
}

data "aws_route53_zone" "realm" {
  for_each     = toset([for r in var.realm_listeners : r.zone if r.zone != ""])
  name         = each.value
  private_zone = false
}

resource "aws_route53_record" "realm" {
  for_each = { for id, r in local.realm_listeners : id => r if r.zone != "" }
  zone_id  = data.aws_route53_zone.realm[each.value.zone].zone_id
  name     = each.value.hostname
  type     = "CNAME"
  ttl      = 300
  records  = [aws_lb.realm[each.key].dns_name]
}

output "realm_listener_settings" {
  description = <<-EOT
    For each entry of realm_listeners, the /admin-api calls that give the realm
    the listener this stack put a load balancer in front of (#99, #472): the
    listener in the realm's listeners.realm, and every application of the
    realm advertised on it while the main port still answers them.
  EOT
  value = {
    for id, r in local.realm_listeners : id => [
      "POST /realm/${id}/admin-api/listeners/set-listeners {\"value\":[{\"id\":\"rl-${substr(md5(id), 0, 8)}\",\"port\":${r.port},\"publicBaseUrl\":\"https://${r.hostname}\",\"hostnames\":[\"${r.hostname}\"]}]}",
      "POST /realm/${id}/admin-api/listeners/set-applications {\"value\":{\"*\":{\"listeners\":[\"main\",\"rl-${substr(md5(id), 0, 8)}\"],\"advertised\":\"rl-${substr(md5(id), 0, 8)}\"}}}",
      "load balancer: ${aws_lb.realm[id].dns_name}"
    ]
  }
}
