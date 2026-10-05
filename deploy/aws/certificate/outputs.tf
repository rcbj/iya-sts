# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

# Read by the environment stack (environment/dns.tf) through
# terraform_remote_state. The VALIDATED certificate's ARN, so nothing can be
# handed a certificate ACM has not issued yet.
output "certificate_arn" {
  description = "The exportable ACM certificate every node presents on 8081; empty when public_hostname is not set."
  value       = local.public_name ? aws_acm_certificate_validation.public[0].certificate_arn : ""
}

output "public_hostname" {
  description = "The name the certificate is for, so the environment can refuse a certificate for another name."
  value       = var.public_hostname
}
