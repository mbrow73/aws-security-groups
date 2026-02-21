# AWS Security Group Platform - AWS Provider Configuration
#
# REPLACE THE PLACEHOLDER VALUES:
# 1. Replace YOUR_ACCOUNT_ID with your actual 12-digit AWS account ID
# 2. Update the assume_role configuration if needed
# 3. Update default_tags as appropriate for your organization

provider "aws" {
  region = var.aws_region
  
  # Optional: Uncomment and configure for cross-account deployments
  # assume_role {
  #   role_arn     = "arn:aws:iam::YOUR_ACCOUNT_ID:role/TerraformExecutionRole"
  #   session_name = "sg-platform-deployment"
  # }
  
  default_tags {
    tags = {
      ManagedBy    = "sg-platform"
      AccountId    = "YOUR_ACCOUNT_ID"  # <-- REPLACE WITH YOUR ACCOUNT ID
      Environment  = var.environment
      Repository   = "aws-security-groups"
      Terraform    = "true"
      DeployedBy   = "terraform-cloud"
    }
  }
}

# Data sources for validation and context
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Account ID validation
locals {
  expected_account_id = "YOUR_ACCOUNT_ID"  # <-- REPLACE WITH YOUR ACCOUNT ID
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