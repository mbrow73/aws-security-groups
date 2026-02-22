# Baseline Module Variables

variable "account_id" {
  description = "AWS Account ID where resources will be deployed"
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Account ID must be a 12-digit number."
  }
}

variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID where security groups will be created. Use 'auto' for automatic discovery."
  type        = string
  default     = "auto"

  validation {
    condition     = var.vpc_id == "auto" || can(regex("^vpc-[a-f0-9]{8}([a-f0-9]{9})?$", var.vpc_id))
    error_message = "VPC ID must be 'auto' or a valid VPC ID (vpc-xxxxxxxx)."
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "baseline_profiles" {
  description = "List of baseline profiles to deploy: vpc-endpoints, eks-standard, eks-internet"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for profile in var.baseline_profiles :
      contains(["vpc-endpoints", "eks-standard", "eks-internet"], profile)
    ])
    error_message = "Valid profiles: vpc-endpoints, eks-standard, eks-internet."
  }
}
