# AWS Security Group Platform - Example Provider Configuration

provider "aws" {
  region = var.aws_region
  
  # Example: Cross-account deployment configuration
  # Uncomment and customize if deploying from a different account
  # assume_role {
  #   role_arn     = "arn:aws:iam::123456789012:role/TerraformExecutionRole"
  #   session_name = "sg-platform-deployment"
  # }
  
  default_tags {
    tags = {
      ManagedBy    = "sg-platform"
      AccountId    = "123456789012"  # Example account ID
      Environment  = var.environment
      Repository   = "aws-security-groups"
      Terraform    = "true"
      DeployedBy   = "terraform-cloud"
      Purpose      = "example"
    }
  }
}

# Data sources for validation and context
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Account ID validation
locals {
  expected_account_id = "123456789012"  # Example account ID
  actual_account_id   = data.aws_caller_identity.current.account_id
  
  # Ensure we're deploying to the correct account
  account_match = local.expected_account_id == local.actual_account_id
}

# Terraform 1.5+ validation check
check "account_validation" {
  assert {
    condition     = local.account_match
    error_message = <<-EOF
      Account ID mismatch detected!
      Expected: ${local.expected_account_id}
      Actual:   ${local.actual_account_id}
      
      Please verify:
      1. Your AWS credentials are for the correct account
      2. The backend configuration points to the right workspace
      3. The account ID in this file matches your YAML configuration
    EOF
  }
}

# Output account information for debugging
output "account_info" {
  description = "Account validation information"
  value = {
    expected_account = local.expected_account_id
    actual_account   = local.actual_account_id
    region          = data.aws_region.current.name
    account_alias   = try(data.aws_iam_account_alias.current.account_alias, "none")
  }
}

# Optional: Get account alias for friendly identification
data "aws_iam_account_alias" "current" {}