# AWS Security Group Platform - Shared Terraform Configuration
# This shared configuration reads security-groups.yaml from the account directory
# based on the account_id variable set per TFC workspace

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Account module - reads security-groups.yaml from the specific account directory
module "account" {
  source = "../modules/account"
  
  # Path to the YAML configuration file for this account
  yaml_file = "${path.module}/../accounts/${var.account_id}/security-groups.yaml"
}