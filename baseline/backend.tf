# AWS Security Group Platform - Baseline Module Backend Configuration

terraform {
  cloud {
    organization = "ORGANIZATION_NAME"  # Replace with your TFC organization name
    
    workspaces {
      name = "sg-platform-baseline"
    }
  }
}

# Backend configuration validation
# These data sources help validate the backend configuration is working correctly

data "terraform_remote_state" "validation" {
  # This is used to validate that the backend is properly configured
  # and accessible. It will fail if there are backend issues.
  
  backend = "s3"
  config = {
    # These values should match the backend configuration above
    # They will be provided via backend-config during init
    bucket = "placeholder-will-be-overridden"
    key    = "validation/terraform.tfstate"
    region = "us-east-1"
  }
  
  # Use a lifecycle to prevent this from running during normal operations
  lifecycle {
    prevent_destroy = true
  }
  
  # This data source is optional and only used for validation
  count = 0  # Disabled by default
}

# State file metadata for tracking and debugging
resource "local_file" "state_metadata" {
  filename = "${path.module}/.terraform-metadata.json"
  
  content = jsonencode({
    account_id = var.account_id
    region     = var.region
    workspace  = terraform.workspace
    backend = {
      type = "s3"
      key  = "security-groups/baseline/${var.account_id}/terraform.tfstate"
    }
    deployment = {
      timestamp = timestamp()
      user      = try(data.aws_caller_identity.current.user_id, "unknown")
      arn       = try(data.aws_caller_identity.current.arn, "unknown")
    }
  })
  
  # Only create this file if running locally (not in CI/CD)
  count = terraform.workspace == "default" ? 1 : 0
  
  depends_on = [data.aws_caller_identity.current]
}

# Get current AWS caller identity for metadata
data "aws_caller_identity" "current" {}

# Terraform state management helpers
locals {
  # State file naming convention
  state_key_baseline = "security-groups/baseline/${var.account_id}/terraform.tfstate"
  state_key_account  = "security-groups/accounts/${var.account_id}/terraform.tfstate"
  
  # Backend metadata
  backend_metadata = {
    state_isolation = "per-account"
    encryption      = "AES256"
    versioning      = "enabled"
    locking        = "dynamodb"
    region         = var.region
  }
}

# Output backend information for debugging
output "backend_configuration" {
  description = "Backend configuration metadata"
  value = {
    type           = "s3"
    state_key      = local.state_key_baseline
    workspace      = terraform.workspace
    account_id     = var.account_id
    region         = var.region
    metadata       = local.backend_metadata
  }
  
  # Don't show sensitive backend details in normal output
  sensitive = false
}