# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

output "members" {
  description = "Each member's PEP_NAME, with its ECS service and notify URL."
  value = {
    for m, v in local.members : m => {
      service    = aws_ecs_service.member[m].name
      tasks      = v.desired
      notify_url = "https://${local.service_host}:${local.notify_ports[m]}/notify"
      secret     = data.aws_secretsmanager_secret.member[m].name
    }
  }
}

output "decision_url" {
  description = "The decision API and AuthZEN edge PDP, round robin over the members."
  value       = "https://${local.direct_host}:${var.decision_port}"
}

output "proxy_url" {
  description = "The reverse proxy, sticky by client address. Also the cluster's publicBaseUrl."
  value       = "https://${local.direct_host}:${var.proxy_port}"
}

output "pdp_url" {
  description = "PEP_PDP_URL: the service, as every member dials it."
  value       = local.pdp_url
}

output "credential_mode" {
  value = var.credential_mode
}

output "autoscaling" {
  value = local.autoscaling ? { min = var.instance_count, max = var.autoscaling_max, cpu_target = var.autoscaling_cpu_target } : null
}
