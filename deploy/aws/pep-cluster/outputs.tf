# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

output "public_url" {
  description = "The reverse proxy, through the WAF and the load balancer: the cluster's publicBaseUrl."
  value       = "https://${var.public_hostname}"
}

output "decision_url" {
  description = "The decision API and AuthZEN edge PDP, round robin over the members."
  value       = var.publish_decision_api ? "https://${var.public_hostname}:${var.decision_port}" : null
}

output "egress_ip" {
  description = "The ONE address the members reach the identity service from (the NAT gateway). The identity service must admit it — for an iya-sts environment, in its ALLOWED_CIDR."
  value       = aws_eip.nat.public_ip
}

output "members" {
  description = "Each member's PEP_NAME, with its ECS service, notify URL (when notify_cidrs) and secret."
  value = {
    for m, v in local.members : m => {
      service    = aws_ecs_service.member[m].name
      tasks      = v.desired
      notify_url = local.notify ? "https://${var.public_hostname}:${local.notify_ports[m]}/notify" : null
      secret     = data.aws_secretsmanager_secret.member[m].name
    }
  }
}

output "pdp_url" {
  description = "PEP_PDP_URL: the identity service, as every member dials it."
  value       = local.pdp_url
}

output "credential_mode" {
  value = var.credential_mode
}

output "nudged" {
  description = "Whether the identity service can nudge the members (notify_cidrs). false: provision.sh stops nudging their rows and they poll."
  value       = local.notify
}

output "autoscaling" {
  value = local.autoscaling ? { min = var.instance_count, max = var.autoscaling_max, cpu_target = var.autoscaling_cpu_target } : null
}

output "companion_upstream" {
  description = "With companion = true: the upstream a cluster route names to reach each member's own companion."
  value       = var.companion ? "http://127.0.0.1:${local.companion_port}" : null
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.main.arn
}
