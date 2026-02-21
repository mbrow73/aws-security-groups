# AWS Security Group Platform - Example Account Configuration
# 
# This demonstrates the new yamldecode() approach - no code generation needed!
# Terraform reads the security-groups.yaml file directly.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Account module - reads security-groups.yaml directly using yamldecode()
module "account" {
  source = "../../modules/account"
  
  # Path to the YAML configuration file
  yaml_file = "${path.module}/security-groups.yaml"
  
  # Example: Additional tags beyond those in the YAML
  additional_tags = {
    Purpose      = "example-demonstration"
    Documentation = "shows-yamldecode-approach"
  }
  
  # Example: Enable advanced features for demonstration
  enable_detailed_monitoring = true
  create_flow_logs          = false  # Disabled to avoid costs in example
  enable_security_insights  = false  # Disabled to avoid costs in example
  
  # Example: Enable compliance mode
  compliance_mode = "none"  # Set to sox, pci, hipaa, iso27001 as needed
}