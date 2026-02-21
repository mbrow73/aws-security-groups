# AWS Security Group Platform - Terraform Cloud Backend Configuration
#
# REPLACE THE PLACEHOLDER VALUES:
# 1. Replace YOUR_ACCOUNT_ID with your actual 12-digit AWS account ID
# 2. Replace YOUR_ORG_NAME with your Terraform Cloud organization name
# 3. Update the workspace name if you use a different naming convention

terraform {
  cloud {
    organization = "YOUR_ORG_NAME"  # <-- REPLACE WITH YOUR TFC ORG NAME
    
    workspaces {
      name = "sg-platform-YOUR_ACCOUNT_ID"  # <-- REPLACE YOUR_ACCOUNT_ID
    }
  }
  
  # Alternative: If using Terraform Enterprise, use this format instead:
  # backend "remote" {
  #   hostname     = "your-tfe-hostname.com"
  #   organization = "YOUR_ORG_NAME"
  #   
  #   workspaces {
  #     name = "sg-platform-YOUR_ACCOUNT_ID"
  #   }
  # }
  
  # Alternative: If using S3 backend, use this format instead:
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "security-groups/accounts/YOUR_ACCOUNT_ID/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}