# ---------------------------------------------------------------------------
# THE PUBLIC FRONT DOOR: AN NLB, 443 → 8081 AND TWO MORE PORTS, TLS PASSED
# THROUGH. locals.tf's `published_ports` lists them and says which job needs
# each; a listener and a target group per entry. It was 443 and three more
# until 2026-09-16, when the service's 9443 mutual-TLS listener was deleted —
# see that file's note; nothing here names the port, so the map lost a row and
# this file lost a listener and a target group with no edit.
#
# Network and not application load balancer, because mock-sts terminates its
# own TLS and a client certificate presented to the main port only reaches the
# service if the TCP stream does. Each node presents its own leaf
# and every leaf chains to the cluster's one Root (tls/CLAUDE.md), so a client
# that trusts the Root trusts whichever node it lands on.
#
# PROXY PROTOCOL V2 ON, CLIENT-IP PRESERVATION OFF. With preservation on, the
# node sees the client's address as its peer and refuses it as an untrusted
# proxy; with v2 on, the NLB's address is the peer and the header carries the
# client's. `STS_TRUSTED_PROXIES` is the public subnets, where the NLB's
# addresses are.
#
# TLS IS PASSED THROUGH IN EVERY ENVIRONMENT, INCLUDING A NAMED ONE
# (2026-09-17). The https listener and its target group are TCP whatever
# `public_hostname` says, and what a client's TLS reaches is the node.
#
# IT TERMINATED HERE WHEN A NAME WAS SET, FOR ONE DAY, AND THAT WAS THE BUG.
# The listener became TLS on the public ACM certificate so that a browser
# trusted the name — and **an NLB cannot pass a client certificate through a
# TLS listener**, so the main port saw none and `GET /tls/sign-in` and RFC
# 8705 stopped working on the one deployment anybody would point a real client
# at. The public certificate moved to the NODE instead (dns.tf,
# deploy/aws/cert-init/): it is exported into the task before the node starts
# and served through `tls.certificateFile`, so the name is trusted AND the
# client certificate arrives. Nothing here is conditional on the name any
# more, which is why `var.tls_policy` and the certificate ARN are gone from
# this file.
#
# CROSS-ZONE ON. Without it an NLB address in one AZ reaches only that AZ's
# node, and `sts_cluster_alternation` — which requires every node to answer —
# would see one.
# ---------------------------------------------------------------------------
resource "aws_lb" "main" {
  name                             = local.prefix
  load_balancer_type               = "network"
  internal                         = false
  subnets                          = aws_subnet.public[*].id
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = false
}

resource "aws_lb_target_group" "nodes" {
  for_each = local.published_ports

  name                   = "${local.prefix}-${each.value.container}"
  port                   = each.value.container
  protocol               = "TCP"
  target_type            = "ip"
  vpc_id                 = aws_vpc.main.id
  proxy_protocol_v2      = true
  preserve_client_ip     = "false"
  deregistration_delay   = 30
  connection_termination = true

  # mock-sts accepts the PROXY v2 LOCAL header the NLB sends on a health
  # check. Where the port speaks HTTP the check is a GET of /healthcheck
  # (2026-09-21): it completes the TLS handshake and asks the process to
  # answer, where a bare TCP connect only asked whether the socket accepted —
  # and on 8081 read as a failed handshake, logged once a second per node.
  # LDAP, LDAPS and Kerberos stay a TCP connect; there is nothing to GET.
  health_check {
    protocol            = each.value.health
    port                = "traffic-port"
    path                = each.value.health == "TCP" ? null : "/healthcheck"
    matcher             = each.value.health == "TCP" ? null : "200"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "ports" {
  for_each = local.published_ports

  load_balancer_arn = aws_lb.main.arn
  port              = each.value.listener
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nodes[each.key].arn
  }
}

# The main port's target group and listener were single resources before the
# other ports were published; these keep them rather than replacing them.
moved {
  from = aws_lb_target_group.nodes
  to   = aws_lb_target_group.nodes["https"]
}

moved {
  from = aws_lb_listener.https
  to   = aws_lb_listener.ports["https"]
}
