# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#695, 2026-11-04): `terraform test` with
# every AWS data source mocked and the environment's state overridden, so
# nothing is read from or made in AWS and no credential is needed. It holds
# the suite task's Workload API sidecar: the service's own image at the tag
# the nodes run, the agent as what the container becomes, the token read from
# a file and never from argv, the shared directory the suite is told about,
# not essential and nothing waiting on it; and the three containers it joined
# unchanged in name.
#
#   terraform -chdir=deploy/aws/suite-callbacks init -backend=false
#   terraform -chdir=deploy/aws/suite-callbacks test
#
# Not run by the suite or CI; run it after changing this stack
# (deploy/aws/CLAUDE.md, *What was checked*).
# ---------------------------------------------------------------------------
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_ecr_repository" {
    defaults = { repository_url = "111122223333.dkr.ecr.us-west-2.amazonaws.com/iya-sts" }
  }
  mock_data "aws_vpc" {
    defaults = { id = "vpc-1", cidr_block = "10.40.0.0/16" }
  }
  mock_data "aws_subnets" {
    defaults = { ids = ["subnet-b", "subnet-a"] }
  }
  mock_data "aws_subnet" {
    defaults = { id = "subnet-a", availability_zone = "us-west-2a" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_data "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/iya-sts-workload-boundary" }
  }
  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/iya-sts-env-testidp-exec" }
  }
}

override_data {
  target = data.terraform_remote_state.environment
  values = { outputs = {
    service_url                 = "https://test-idp.example.test"
    public_hostname             = "test-idp.example.test"
    nlb_dns_name                = "nlb.example.test"
    image_tag                   = "abc123def456"
    load_balancer_ports         = { https = { listener = 443 }, ldap = { listener = 389 } }
    spiffe_default_ports        = { server = 8181 }
    container_log_group         = "/iya-sts/containers"
    reports_bucket              = "iya-sts-test-reports-111122223333"
    admin_api_client_secret_arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:admin"
    ecs_services                = { a = "a", b = "b", c = "c" }
    ecs_cluster                 = "iya-sts-testidp"
  } }
}

variables {
  environment = "testidp"
  image_tag   = "0123456789ab-deadbeef"
}

run "the_workload_agent_is_a_sidecar_from_the_service_image" {
  command = plan

  assert {
    condition = (
      [for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) : c.name] ==
      ["pep-credential", "xacml-pep", "spiffe-agent", "suite"]
    )
    error_message = "the task's containers are the three it had and the sidecar"
  }
  assert {
    condition = one([
      for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) :
      c.image if c.name == "spiffe-agent"
    ]) == "111122223333.dkr.ecr.us-west-2.amazonaws.com/iya-sts:abc123def456"
    error_message = "the sidecar runs the service image at the tag the nodes run, not a runner- or tree tag"
  }
  assert {
    condition = one([
      for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) :
      c if c.name == "spiffe-agent"
    ]).essential == false
    error_message = "the sidecar is not essential"
  }
  assert {
    condition = alltrue([
      for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) :
      !contains([for d in try(c.dependsOn, []) : d.containerName], "spiffe-agent")
    ])
    error_message = "no container waits on the sidecar"
  }
  assert {
    condition = (
      one([for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) : c if c.name == "spiffe-agent"]).entryPoint == ["bash", "-c"] &&
      strcontains(one([for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) : c if c.name == "spiffe-agent"]).command[0], "exec node /usr/src/sts/spiffe/workload_agent.js")
    )
    error_message = "the container becomes the compiled workload agent"
  }
  assert {
    condition = (
      strcontains(local.spiffe_agent_script, "--join-token-file=\"$D/join-token\"") &&
      strcontains(local.spiffe_agent_script, "--ready-file=\"$D/ready\"") &&
      strcontains(local.spiffe_agent_script, "\"$${A[@]}\"") &&
      !strcontains(local.spiffe_agent_script, "--join-token=") &&
      !strcontains(local.spiffe_agent_script, "--join-token \"")
    )
    error_message = local.spiffe_agent_script
  }
  assert {
    condition = contains(
      one([for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) : c if c.name == "suite"]).environment,
      { name = "STS_SPIFFE_AGENT_DIR", value = "/shared/spiffe" }
    )
    error_message = "the suite is told where the sidecar's directory is"
  }
  assert {
    condition = alltrue([
      for c in jsondecode(aws_ecs_task_definition.callbacks.container_definitions) :
      contains(c.mountPoints, { sourceVolume = "shared", containerPath = "/shared" })
      if contains(["spiffe-agent", "suite"], c.name)
    ])
    error_message = "the sidecar and the suite share the volume the socket is on"
  }
  assert {
    condition     = contains(keys(local.listener_ports), "spiffe-server")
    error_message = "the task (and so the sidecar) is admitted to the SPIRE Server API port"
  }
}
