# AWS Security Group Platform - Terraform Cloud Backend Configuration
# 
# This shared backend configuration is used by all account workspaces.
# The workspace name is set in the TFC workspace itself, not in this file.
# Each workspace has a variable 'account_id' that identifies which account to deploy to.

terraform {
  cloud {
    organization = "ORGANIZATION_NAME"  # Replace with your TFC organization name
  }
}