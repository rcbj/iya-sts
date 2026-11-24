# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE LOAD BALANCER: an internet-facing ALB, a public ACM certificate for
# `public_hostname`, and the WAF (waf.tf) in front of all of it.
#
#   443             the reverse proxy (the members' 9543), STICKY BY COOKIE
#   80              redirected to 443
#   decision_port   the decision API and AuthZEN (the members' 9443), round
#                   robin — each decision stands alone
#   notify ports    with notify_cidrs: member n's own 9443, for the nudge
#
# THE ALB ENDS TLS AND OPENS A NEW TLS CONNECTION TO THE MEMBER, to the pair
# the realm issued it; an ALB does not verify a target's certificate, so the
# pair's names do not matter here. What a client sees is only the public
# certificate. The price is the client certificate: none reaches a member, so
# an AuthZEN caller admitted by mutual TLS cannot use this listener
# (variables.tf, `publish_decision_api`).
#
# EVERY TARGET GROUP ASKS THE MEMBER'S 9443 /healthcheck, the image's own
# liveness question: the proxy listener answers only once a route exists,
# and a member with no route is still a live member.
# ---------------------------------------------------------------------------

data "aws_route53_zone" "public" {
  name         = var.public_zone_name
  private_zone = false
}

resource "aws_acm_certificate" "public" {
  domain_name       = var.public_hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for o in aws_acm_certificate.public.domain_validation_options : o.domain_name => o
  }
  zone_id         = data.aws_route53_zone.public.zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "public" {
  certificate_arn         = aws_acm_certificate.public.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

resource "aws_lb" "main" {
  name                       = local.prefix
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = false
  idle_timeout               = 60
}

resource "aws_route53_record" "public" {
  zone_id = data.aws_route53_zone.public.zone_id
  name    = var.public_hostname
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = false
  }
}

locals {
  # TLS 1.3, and 1.2 with forward-secret AEAD suites only.
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  health_check = {
    protocol            = "HTTPS"
    port                = tostring(local.pep_https_port)
    path                = "/healthcheck"
    matcher             = "200"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "proxy" {
  name                 = "${local.prefix}-proxy"
  port                 = local.pep_proxy_port
  protocol             = "HTTPS"
  target_type          = "ip"
  vpc_id               = aws_vpc.main.id
  deregistration_delay = 30

  # A browser stays on one member for the length of its session: the
  # sign-in waiting for its callback, the session and its tokens, and the
  # DPoP key they are bound to all live in that member.
  stickiness {
    type            = "lb_cookie"
    cookie_duration = 86400
    enabled         = true
  }

  health_check {
    protocol            = local.health_check.protocol
    port                = local.health_check.port
    path                = local.health_check.path
    matcher             = local.health_check.matcher
    interval            = local.health_check.interval
    healthy_threshold   = local.health_check.healthy_threshold
    unhealthy_threshold = local.health_check.unhealthy_threshold
  }
}

resource "aws_lb_target_group" "decision" {
  count                = var.publish_decision_api ? 1 : 0
  name                 = "${local.prefix}-decision"
  port                 = local.pep_https_port
  protocol             = "HTTPS"
  target_type          = "ip"
  vpc_id               = aws_vpc.main.id
  deregistration_delay = 30

  health_check {
    protocol            = local.health_check.protocol
    port                = local.health_check.port
    path                = local.health_check.path
    matcher             = local.health_check.matcher
    interval            = local.health_check.interval
    healthy_threshold   = local.health_check.healthy_threshold
    unhealthy_threshold = local.health_check.unhealthy_threshold
  }
}

resource "aws_lb_target_group" "notify" {
  for_each             = local.notify_ports
  name                 = "${local.prefix}-n${each.value}"
  port                 = local.pep_https_port
  protocol             = "HTTPS"
  target_type          = "ip"
  vpc_id               = aws_vpc.main.id
  deregistration_delay = 10

  health_check {
    protocol            = local.health_check.protocol
    port                = local.health_check.port
    path                = local.health_check.path
    matcher             = local.health_check.matcher
    interval            = local.health_check.interval
    healthy_threshold   = local.health_check.healthy_threshold
    unhealthy_threshold = local.health_check.unhealthy_threshold
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = local.ssl_policy
  certificate_arn   = aws_acm_certificate_validation.public.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.proxy.arn
  }
}

resource "aws_lb_listener" "decision" {
  count             = var.publish_decision_api ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = var.decision_port
  protocol          = "HTTPS"
  ssl_policy        = local.ssl_policy
  certificate_arn   = aws_acm_certificate_validation.public.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.decision[0].arn
  }
}

resource "aws_lb_listener" "notify" {
  for_each          = local.notify_ports
  load_balancer_arn = aws_lb.main.arn
  port              = each.value
  protocol          = "HTTPS"
  ssl_policy        = local.ssl_policy
  certificate_arn   = aws_acm_certificate_validation.public.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.notify[each.key].arn
  }
}
