# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AN OFFLINE RENDER OF THIS STACK (#367, 2026-09-30): `terraform test` with
# a provider that is never asked anything (every AWS-reading data source and the replica module overridden), so nothing is read from or made in AWS and no credential is needed.
# It holds the mesh and the replicas: globalidp's fifteen peerings, five replicas and thirty zone associations, the pair orientation, testidpna keeping its one pair and replica under the same keys (the `moved` blocks' targets), and a cell id that does not name its region refused.
#
#   terraform -chdir=deploy/aws/global init -backend=false
#   terraform -chdir=deploy/aws/global test
#
# Not run by the suite or CI; run it after changing this stack
# (deploy/aws/CLAUDE.md, *What was checked*).
# ---------------------------------------------------------------------------
provider "aws" {
  region                      = "us-west-2"
  access_key                  = "x"
  secret_key                  = "x"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
override_data {
  target = data.aws_caller_identity.current
  values = { account_id = "111122223333" }
}
override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}
override_data {
  target = data.aws_kms_key.global
  values = { arn = "arn:aws:kms:us-west-2:111122223333:key/mrk-1" }
}
override_data {
  target = data.terraform_remote_state.cell
  values = { outputs = {
    vpc_id                 = "vpc-1", vpc_cidr = "10.0.0.0/16",
    route_table_ids        = { public = "rtb-1", private = "rtb-2" },
    global_db_subnet_group = "sg", global_db_security_group_id = "sg-1",
    intercell_zone_id      = "Z1"
  } }
}
override_module {
  target  = module.replica
  outputs = { address = "replica.example" }
}
override_resource {
  target          = aws_db_instance.primary
  override_during = plan
  values          = { arn = "arn:aws:rds:us-west-2:111122223333:db:x", address = "primary.example" }
}
run "globalidp" {
  command = plan
  variables {
    environment   = "globalidp"
    primary_cell  = "usw2"
    cells         = jsondecode(file("../environment/envs/globalidp.cells.tfvars.json")).cells
    jurisdictions = jsondecode(file("../environment/envs/globalidp.cells.tfvars.json")).jurisdictions
  }
  assert {
    condition     = length(module.peering) == 15 && length(module.replica) == 5 && !contains(keys(module.replica), "usw2")
    error_message = "pairs=${length(module.peering)} replicas=${jsonencode(keys(module.replica))}"
  }
  assert {
    condition     = sort(keys(local.pairs)) == sort(["usw2_apse1", "usw2_apse5", "usw2_euc1", "usw2_euw1", "usw2_use2", "apse1_apse5", "apse1_euc1", "apse1_euw1", "apse1_use2", "apse5_euc1", "apse5_euw1", "apse5_use2", "euc1_euw1", "euc1_use2", "euw1_use2"])
    error_message = jsonencode(keys(local.pairs))
  }
  assert {
    condition     = local.pairs["apse1_euw1"].requester.region == "ap-southeast-1" && local.pairs["apse1_euw1"].accepter.region == "eu-west-1"
    error_message = "orientation"
  }
  assert {
    condition     = length(aws_route53_zone_association.intercell) == 30
    error_message = "associations"
  }
}
run "testidpna_keeps_its_pair" {
  command = plan
  variables {
    environment   = "testidpna"
    primary_cell  = "usw2"
    cells         = jsondecode(file("../environment/envs/testidpna.cells.tfvars.json")).cells
    jurisdictions = jsondecode(file("../environment/envs/testidpna.cells.tfvars.json")).jurisdictions
  }
  assert {
    condition     = keys(local.pairs) == ["usw2_cac1"] && keys(module.replica) == ["cac1"]
    error_message = jsonencode(keys(local.pairs))
  }
}
run "bad_id_refused" {
  command = plan
  variables {
    environment  = "x1"
    primary_cell = "usw2"
    cells        = { usw2 = { region = "us-west-2", jurisdiction = "us", vpc_cidr = "10.1.0.0/16" }, euc9 = { region = "eu-west-1", jurisdiction = "eu", vpc_cidr = "10.2.0.0/16" } }
  }
  expect_failures = [var.cells]
}
