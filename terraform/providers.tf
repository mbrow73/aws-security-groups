# AWS Security Group Platform - AWS Provider Configuration
# This shared provider configuration assumes role into the target account
# based on the account_id variable set per TFC workspace

provider "aws" {
  region = var.aws_region
  
  # Assume role into the target account's SecurityGroupApplierRole
  assume_role {
    role_arn     = "arn:aws:iam::${var.account_id}:role/SecurityGroupApplierRole"
    session_name = "sg-platform-deployment"
  }
  
  default_tags {
    tags = {
      ManagedBy    = "sg-platform"
      AccountId    = var.account_id
      Repository   = "aws-security-groups"
      Terraform    = "true"
      DeployedBy   = "terraform-cloud"
    }
  }
}

# Data sources for validation and context
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Account ID validation - ensure we're deploying to the correct account
locals {
  expected_account_id = var.account_id
  actual_account_id   = data.aws_caller_identity.current.account_id
  
  # Ensure we're deploying to the correct account
  account_match = local.expected_account_id == local.actual_account_id
}

# Fail early if we're in the wrong account
check "account_validation" {
  assert {
    condition     = local.account_match
    error_message = "Account ID mismatch! Expected ${local.expected_account_id}, got ${local.actual_account_id}. Check your AWS credentials and backend configuration."
  }
}