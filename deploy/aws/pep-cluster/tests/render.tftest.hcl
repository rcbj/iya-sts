# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#1284): `terraform test` with every AWS
# data source mocked, so nothing is read from or made in AWS and no
# credential is needed. It holds the standalone environment's shape — its
# own network with private members behind one NAT, an ALB with the regional
# WAF in front of it and a sticky proxy, no key in a task definition, the
# optional nudge, the companion sidecar — and the refusals.
#
#   terraform -chdir=deploy/aws/pep-cluster init -backend=false
#   terraform -chdir=deploy/aws/pep-cluster test
#
# Not run by the suite or CI; run it after changing this stack.
# ---------------------------------------------------------------------------
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-west-2b", "us-west-2a", "us-west-2c"] }
  }
  mock_data "aws_ecr_repository" {
    defaults = {
      repository_url = "111122223333.dkr.ecr.us-west-2.amazonaws.com/iya-sts"
      arn            = "arn:aws:ecr:us-west-2:111122223333:repository/iya-sts"
    }
  }
  mock_data "aws_cloudwatch_log_group" {
    defaults = { name = "/iya-sts/containers", arn = "arn:aws:logs:us-west-2:111122223333:log-group:/iya-sts/containers" }
  }
  mock_data "aws_route53_zone" {
    defaults = { zone_id = "Z1" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_data "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/iya-sts-workload-boundary" }
  }
  mock_data "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-west-2:111122223333:key/k" }
  }
  mock_data "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/testpep/pep/aws/m-AbCdEf" }
  }
}

# The real provider knows a certificate's validation names at plan; the mock
# does not, and the validation records are keyed by them.
override_resource {
  target          = aws_acm_certificate.public
  override_during = plan
  values = {
    arn = "arn:aws:acm:us-west-2:111122223333:certificate/c"
    domain_validation_options = [{
      domain_name           = "test-pep.example.test"
      resource_record_name  = "_x.test-pep.example.test."
      resource_record_type  = "CNAME"
      resource_record_value = "_y.acm-validations.aws."
    }]
  }
}

variables {
  environment      = "testpep"
  idp_url          = "https://test-idp.example.test/"
  public_hostname  = "test-pep.example.test"
  public_zone_name = "example.test"
  allowed_cidrs    = ["203.0.113.4/32"]
  image_tag        = "abc123def456"
}

run "a_network_of_its_own_with_private_members" {
  command = plan

  assert {
    condition     = aws_vpc.main.cidr_block == "10.60.0.0/16" && length(aws_subnet.private) == 2 && length(aws_subnet.public) == 2
    error_message = "its own VPC, two zones, public and private subnets"
  }
  assert {
    condition     = alltrue([for s in aws_ecs_service.member : !s.network_configuration[0].assign_public_ip])
    error_message = "the members have no public address"
  }
  assert {
    condition     = keys(aws_ecs_service.member) == ["aws-pep-1", "aws-pep-2"]
    error_message = "two members by default, named <cluster>-pep-<n>"
  }
  assert {
    condition     = aws_ecs_cluster.main.name == "iya-sts-testpep"
    error_message = "an ECS cluster of its own"
  }
}

run "the_waf_is_in_front_of_the_alb" {
  command = plan

  assert {
    condition     = aws_lb.main.load_balancer_type == "application"
    error_message = "WAF attaches to an ALB, never an NLB"
  }
  assert {
    condition     = aws_wafv2_web_acl.main.scope == "REGIONAL" && length(aws_wafv2_web_acl.main.default_action[0].block) == 1
    error_message = "a regional ACL that blocks what no rule allows"
  }
  assert {
    condition = toset([for r in aws_wafv2_web_acl.main.rule : r.name]) == toset([
      "aws-ip-reputation", "aws-known-bad-inputs", "aws-common", "rate-per-address", "allowed",
    ])
    error_message = "the three managed groups, the rate limit and the allowlist"
  }
  assert {
    condition     = one([for r in aws_wafv2_web_acl.main.rule : r.priority if r.name == "allowed"]) > max([for r in aws_wafv2_web_acl.main.rule : r.priority if r.name != "allowed"]...)
    error_message = "an allowed address is still held to every managed group: the allow comes last"
  }
  assert {
    condition     = aws_wafv2_ip_set.allowed.addresses == toset(["203.0.113.4/32"])
    error_message = "the allowlist is allowed_cidrs"
  }
}

run "one_public_certificate_and_a_sticky_proxy" {
  command = plan

  assert {
    condition     = aws_acm_certificate.public.domain_name == "test-pep.example.test"
    error_message = "the browser sees one public certificate"
  }
  assert {
    condition     = aws_lb_target_group.proxy.stickiness[0].type == "lb_cookie" && aws_lb_target_group.proxy.stickiness[0].enabled
    error_message = "a browser stays on one member, by the load balancer's cookie"
  }
  assert {
    condition     = aws_lb_target_group.proxy.port == 9543 && aws_lb_target_group.proxy.protocol == "HTTPS" && aws_lb_target_group.proxy.health_check[0].port == "9443"
    error_message = "the proxy re-encrypted to 9543, health-checked on 9443"
  }
  assert {
    condition     = aws_lb_listener.decision[0].port == 9443 && aws_lb_target_group.decision[0].port == 9443
    error_message = "the decision API on 9443"
  }
}

run "the_members_pull_from_the_idp_and_hold_no_key" {
  command = plan

  assert {
    condition = alltrue([
      for t in aws_ecs_task_definition.member :
      one([for e in jsondecode(t.container_definitions)[0].environment : e.value if e.name == "PEP_PDP_URL"]) == "https://test-idp.example.test"
    ])
    error_message = "the identity service at its public URL"
  }
  assert {
    condition = alltrue([
      for t in aws_ecs_task_definition.member :
      !strcontains(t.container_definitions, "PRIVATE KEY") && length(jsondecode(t.container_definitions)[0].secrets) == 4
    ])
    error_message = "the keys arrive as Secrets Manager references only"
  }
  assert {
    condition = alltrue([
      for t in aws_ecs_task_definition.member :
      length([for e in jsondecode(t.container_definitions)[0].environment : e if e.name == "PEP_NOTIFY_URL"]) == 0
    ])
    error_message = "with no notify_cidrs nothing advertises a nudge port"
  }
  assert {
    condition     = length(aws_lb_listener.notify) == 0
    error_message = "with no notify_cidrs there is no notify listener"
  }
}

run "the_nudge_when_the_idp_has_fixed_addresses" {
  command = plan

  variables {
    notify_cidrs = ["198.51.100.7/32"]
  }

  assert {
    condition     = { for k, l in aws_lb_listener.notify : k => l.port } == { "aws-pep-1" = 9451, "aws-pep-2" = 9452 }
    error_message = "each member's nudge has a port of its own"
  }
  assert {
    condition = one([
      for e in jsondecode(aws_ecs_task_definition.member["aws-pep-2"].container_definitions)[0].environment :
      e.value if e.name == "PEP_NOTIFY_URL"
    ]) == "https://test-pep.example.test:9452/notify"
    error_message = "a member advertises its own notify port at the public name"
  }
  assert {
    condition     = contains(keys(aws_vpc_security_group_ingress_rule.alb), "9451-198.51.100.7/32") && !contains(keys(aws_vpc_security_group_ingress_rule.alb), "9451-203.0.113.4/32")
    error_message = "the notify ports admit the identity service only"
  }
}

run "the_companion_is_a_sidecar_no_rule_admits" {
  command = plan

  variables {
    companion = true
  }

  assert {
    condition = alltrue([
      for t in aws_ecs_task_definition.member :
      [for c in jsondecode(t.container_definitions) : c.name] == ["xacml-pep", "companion"]
    ])
    error_message = "each member's task carries its own companion"
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.member["aws-pep-1"].container_definitions)[1].essential == false
    error_message = "a stopped companion does not stop the member"
  }
  assert {
    condition     = !contains([for r in aws_vpc_security_group_ingress_rule.pep_from_alb : r.from_port], 9700)
    error_message = "no rule admits the companion's port"
  }
  assert {
    condition     = output.companion_upstream == "http://127.0.0.1:9700"
    error_message = "the route's upstream is each member's own loopback"
  }
}

run "shared_autoscales_when_asked" {
  command = plan

  variables {
    credential_mode = "shared"
    instance_count  = 2
    autoscaling_max = 6
  }

  assert {
    condition     = keys(aws_ecs_service.member) == ["aws-pep"] && aws_appautoscaling_target.shared[0].max_capacity == 6
    error_message = "one member name, two to six tasks"
  }
}

run "a_realm_prefixes_the_pdp_url" {
  command = plan

  variables {
    realm = "acme"
  }

  assert {
    condition     = output.pdp_url == "https://test-idp.example.test/realm/acme"
    error_message = "a realm's members pull from its prefix"
  }
}

run "autoscaling_is_refused_per_instance" {
  command = plan

  variables {
    autoscaling_max = 4
  }

  expect_failures = [aws_ecs_service.member]
}
