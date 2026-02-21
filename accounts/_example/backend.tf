# AWS Security Group Platform - Example Backend Configuration
# This is for demonstration purposes only

terraform {
  cloud {
    organization = "example-org"  # Replace with your TFC organization
    
    workspaces {
      name = "sg-platform-123456789012"  # Example workspace name
    }
  }
  
  # Alternative backends for different scenarios:
  
  # For Terraform Enterprise:
  # backend "remote" {
  #   hostname     = "tfe.company.com"
  #   organization = "company-org"
  #   
  #   workspaces {
  #     name = "sg-platform-123456789012"
  #   }
  # }
  
  # For S3 backend:
  # backend "s3" {
  #   bucket         = "company-terraform-state"
  #   key            = "security-groups/accounts/123456789012/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
  
  # For local development/testing:
  # backend "local" {
  #   path = "./terraform.tfstate"
  # }
}