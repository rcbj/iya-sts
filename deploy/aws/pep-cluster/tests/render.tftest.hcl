# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#1284): `terraform test` with every AWS
# data source mocked and the environment's state overridden, so nothing is
# read from or made in AWS and no credential is needed. It holds the two
# credential arrangements' shapes, that no key reaches the task definition
# except as a Secrets Manager reference, the per-member notify port, the
# proxy's affinity, and the refusals.
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
  mock_data "aws_ecr_repository" {
    defaults = {
      repository_url = "111122223333.dkr.ecr.us-west-2.amazonaws.com/iya-sts"
      arn            = "arn:aws:ecr:us-west-2:111122223333:repository/iya-sts"
    }
  }
  mock_data "aws_lb" {
    defaults = { vpc_id = "vpc-1", arn = "arn:aws:elasticloadbalancing:us-west-2:111122223333:loadbalancer/net/iya-sts-testidp/1" }
  }
  mock_data "aws_subnets" {
    defaults = { ids = ["subnet-c", "subnet-a", "subnet-b"] }
  }
  mock_data "aws_vpc_security_group_rules" {
    defaults = { ids = [] }
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
    defaults = { arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:iya-sts/testidp/pep/aws/m-AbCdEf" }
  }
}

override_data {
  target = data.terraform_remote_state.environment
  values = { outputs = {
    public_hostname     = "test-idp.example.test"
    direct_hostname     = "direct.test-idp.example.test"
    image_tag           = "abc123def456"
    container_log_group = "/iya-sts/containers"
    ecs_cluster         = "iya-sts-testidp"
  } }
}

variables {
  environment = "testidp"
}

run "per_instance_is_one_service_and_one_notify_port_per_member" {
  command = plan

  assert {
    condition     = keys(aws_ecs_service.member) == ["aws-pep-1", "aws-pep-2"]
    error_message = "two members by default, named <cluster>-pep-<n>"
  }
  assert {
    condition     = alltrue([for s in aws_ecs_service.member : s.desired_count == 1])
    error_message = "a per-instance member is one task"
  }
  assert {
    condition     = { for k, l in aws_lb_listener.notify : k => l.port } == { "aws-pep-1" = 9451, "aws-pep-2" = 9452 }
    error_message = "each member's nudge has a load-balancer port of its own"
  }
  assert {
    condition = alltrue([
      for k, t in aws_ecs_task_definition.member :
      one([for e in jsondecode(t.container_definitions)[0].environment : e.value if e.name == "PEP_NOTIFY_URL"]) ==
      "https://test-idp.example.test:${aws_lb_listener.notify[k].port}/notify"
    ])
    error_message = "a member's notify URL is the public name (the load balancer inside the VPC) on its own notify port"
  }
  assert {
    condition = alltrue([
      for k, t in aws_ecs_task_definition.member :
      one([for e in jsondecode(t.container_definitions)[0].environment : e.value if e.name == "PEP_NAME"]) == k
    ])
    error_message = "PEP_NAME is the member's name, which provision.sh registers"
  }
  assert {
    condition = alltrue([
      for t in aws_ecs_task_definition.member :
      one([for e in jsondecode(t.container_definitions)[0].environment : e.value if e.name == "PEP_PDP_URL"]) ==
      "https://test-idp.example.test"
    ])
    error_message = "the PDP URL is the public name, the token endpoint's resource, with no prefix for the default realm"
  }
  assert {
    condition = alltrue([
      for t in aws_ecs_task_definition.member : length(jsondecode(t.container_definitions)[0].secrets) == 4
    ])
    error_message = "the four values arrive as Secrets Manager references"
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.member["aws-pep-1"].container_definitions)[0].image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/iya-sts:pep-abc123def456"
    error_message = "the PEP image is pep-<the environment's tag> by default"
  }
}

run "no_key_material_in_the_task_definition" {
  command = plan

  assert {
    condition = alltrue([
      for t in aws_ecs_task_definition.member :
      !strcontains(t.container_definitions, "PRIVATE KEY") && !strcontains(t.container_definitions, "BEGIN CERTIFICATE")
    ])
    error_message = "nothing PEM is written into a task definition (or this state)"
  }
}

run "the_proxy_is_sticky_and_the_decision_api_is_not" {
  command = plan

  assert {
    condition     = aws_lb_target_group.client["proxy"].stickiness[0].enabled && aws_lb_target_group.client["proxy"].stickiness[0].type == "source_ip"
    error_message = "the reverse proxy keeps a browser on one member"
  }
  assert {
    condition     = !aws_lb_target_group.client["decision"].stickiness[0].enabled
    error_message = "the decision API is round robin"
  }
  assert {
    condition     = aws_lb_target_group.client["proxy"].health_check[0].port == "9443"
    error_message = "the proxy's group asks the member's 9443 /healthcheck, live before any route exists"
  }
}

run "shared_is_one_service_of_n_tasks" {
  command = plan

  variables {
    credential_mode = "shared"
    instance_count  = 3
  }

  assert {
    condition     = keys(aws_ecs_service.member) == ["aws-pep"] && aws_ecs_service.member["aws-pep"].desired_count == 3
    error_message = "one member name, three tasks"
  }
  assert {
    condition     = length(aws_appautoscaling_target.shared) == 0
    error_message = "no autoscaling unless autoscaling_max is above the count"
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
    condition     = aws_appautoscaling_target.shared[0].min_capacity == 2 && aws_appautoscaling_target.shared[0].max_capacity == 6
    error_message = "the count is the floor, autoscaling_max the ceiling"
  }
}

run "a_realm_prefixes_the_pdp_url" {
  command = plan

  variables {
    realm = "acme"
  }

  assert {
    condition = one([
      for e in jsondecode(aws_ecs_task_definition.member["aws-pep-1"].container_definitions)[0].environment :
      e.value if e.name == "PEP_PDP_URL"
    ]) == "https://test-idp.example.test/realm/acme"
    error_message = "a realm's members pull from its prefix"
  }
}

run "autoscaling_is_refused_per_instance" {
  command = plan

  variables {
    autoscaling_max = 4
  }

  expect_failures = [aws_security_group.pep]
}

run "the_clients_are_told_the_direct_name" {
  command = plan

  assert {
    condition     = output.decision_url == "https://direct.test-idp.example.test:9443" && output.proxy_url == "https://direct.test-idp.example.test:9543"
    error_message = "outside the VPC the public name may be CloudFront, which carries 443 only"
  }
}

run "a_port_the_environment_uses_is_refused" {
  command = plan

  variables {
    decision_port = 636
  }

  expect_failures = [aws_security_group.pep]
}
