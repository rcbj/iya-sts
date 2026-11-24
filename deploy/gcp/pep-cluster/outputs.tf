# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# deploy/aws/pep-cluster/outputs.tf's keys, so a script reading either cloud
# reads one set, with `cloud = "gcp"`.

output "public_url" {
  description = "The reverse proxy, through Cloud Armor and the load balancer: the cluster's publicBaseUrl."
  value       = "https://${var.public_hostname}"
}

output "decision_url" {
  description = "The decision API and AuthZEN edge PDP, round robin over the members."
  value       = var.publish_decision_api ? "https://${var.decision_hostname}" : null
}

output "egress_ip" {
  description = "The ONE address the members reach the identity service from (Cloud NAT). The identity service must admit it."
  value       = google_compute_address.egress.address
}

output "lb_address" {
  value = google_compute_global_address.lb.address
}

output "members" {
  description = "Each member's PEP_NAME, with its instance group, notify URL (with notify_cidrs) and secrets."
  value = {
    for m in keys(local.members) : m => {
      group      = local.per_instance ? google_compute_instance_group_manager.member[m].name : google_compute_region_instance_group_manager.shared[0].name
      notify_url = local.notify ? "https://${local.notify_hosts[m]}/notify" : null
      secrets    = [for k, s in local.member_secrets : s.id if s.member == m]
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

output "security_policy" {
  value = google_compute_security_policy.main.name
}

output "cloud" {
  value = "gcp"
}
