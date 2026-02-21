# AWS Security Group Platform - Shared Variables
# These variables are set per-workspace in Terraform Cloud

variable "account_id" {
  description = "AWS Account ID to deploy security groups to (set per TFC workspace)"
  type        = string
  
  validation {
    condition = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Account ID must be a 12-digit number."
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition = can(regex("^[a-z0-9-]+$", var.aws_region))
    error_message = "AWS region must be a valid region identifier."
  }
}