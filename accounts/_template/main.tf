# AWS Security Group Platform - Account Configuration
# 
# This file uses the account module to read security-groups.yaml directly
# No code generation required - Terraform reads the YAML file using yamldecode()
#
# To use this template:
# 1. Copy this entire directory to accounts/YOUR_ACCOUNT_ID/
# 2. Update backend.tf with your account ID and TFC workspace name
# 3. Create your security-groups.yaml file
# 4. Submit a PR - no manual Terraform generation needed!

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Account module - reads security-groups.yaml directly
module "account" {
  source = "../../modules/account"
  
  # Path to your YAML configuration file
  yaml_file = "${path.module}/security-groups.yaml"
  
  # Optional: Additional tags for all resources
  additional_tags = {
    # Add any additional tags here
    # Example:
    # CostCenter = "engineering"
    # Project    = "aws-migration"
  }
  
  # Optional: Enable advanced features
  enable_detailed_monitoring = false
  create_flow_logs          = false
  enable_security_insights  = false
  
  # Optional: Compliance mode
  compliance_mode = "none"  # Options: none, sox, pci, hipaa, iso27001
}