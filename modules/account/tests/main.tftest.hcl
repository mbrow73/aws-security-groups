# Account Module Tests — YAML → Security Groups end-to-end
# Run from modules/account/: terraform test

mock_provider "aws" {}

override_data {
  target = data.aws_vpc.discovered[0]
  values = {
    id         = "vpc-0123456789abcdef0"
    cidr_block = "10.0.0.0/16"
  }
}

variables {
  yaml_file = "tests/fixtures/basic-account.yaml"
}

# --------------------------------------------------
# Test: Account module reads YAML and creates SGs
# --------------------------------------------------
run "account_creates_sgs_from_yaml" {
  command = apply

  assert {
    condition     = output.account_id == "999888777666"
    error_message = "Account ID should match YAML"
  }

  assert {
    condition     = length(output.security_group_ids) == 1
    error_message = "Should create 1 security group from YAML"
  }

  assert {
    condition     = lookup(output.security_group_ids, "app-backend", null) != null
    error_message = "Should create app-backend SG"
  }
}

# --------------------------------------------------
# Test: Multiple SGs from one account YAML
# --------------------------------------------------
run "multi_sg_account" {
  command = apply

  variables {
    yaml_file = "tests/fixtures/multi-sg-account.yaml"
  }

  assert {
    condition     = output.account_id == "111222333444"
    error_message = "Account ID should match YAML"
  }

  assert {
    condition     = length(output.security_group_ids) == 3
    error_message = "Should create 3 security groups"
  }

  assert {
    condition     = lookup(output.security_group_ids, "api-backend", null) != null
    error_message = "Should create api-backend SG"
  }

  assert {
    condition     = lookup(output.security_group_ids, "rds-postgres", null) != null
    error_message = "Should create rds-postgres SG"
  }

  assert {
    condition     = lookup(output.security_group_ids, "redis-cache", null) != null
    error_message = "Should create redis-cache SG"
  }
}
