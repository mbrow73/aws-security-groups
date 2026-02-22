# AWS Security Group Platform - Baseline Module Variables

variable "account_id" {
  description = "AWS Account ID where resources will be deployed"
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Account ID must be a 12-digit number."
  }
}

variable "region" {
  description = "AWS region where resources will be deployed"
  type        = string
  default     = "us-east-1"
  validation {
    condition = contains([
      "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
      "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2"
    ], var.region)
    error_message = "Region must be a supported AWS region."
  }
}

variable "vpc_id" {
  description = "VPC ID where security groups will be created. Use 'auto' for automatic discovery."
  type        = string
  default     = "auto"
  
  validation {
    condition = var.vpc_id == "auto" || can(regex("^vpc-[a-f0-9]{8}([a-f0-9]{9})?$", var.vpc_id))
    error_message = "VPC ID must be 'auto' or a valid VPC ID format (vpc-xxxxxxxx)."
  }
}

variable "environment" {
  description = "Environment name (production, staging, development)"
  type        = string
  default     = ""
  
  validation {
    condition = contains(["", "production", "staging", "development"], var.environment)
    error_message = "Environment must be one of: production, staging, development, or empty string."
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# Baseline Profiles Configuration
variable "baseline_profiles" {
  description = "List of baseline security group profiles to deploy"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for profile in var.baseline_profiles : 
      contains(["vpc-endpoints", "eks-standard", "eks-internet"], profile)
    ])
    error_message = "All baseline profiles must be one of: vpc-endpoints, eks-standard, eks-internet."
  }
}

# Profile-specific Configuration Variables

# VPC Endpoints Profile Variables
variable "additional_vpc_endpoint_ports" {
  description = "Additional ports for VPC endpoint access beyond the standard 80/443"
  type = list(object({
    port    = number
    service = string
  }))
  default = [
    {
      port    = 8080
      service = "custom-api"
    }
  ]
}

# Internet Ingress Profile Variables
variable "waf_custom_ports" {
  description = "Custom ports for WAF/CDN to NLB traffic beyond standard 80/443"
  type        = list(number)
  default     = [8080, 8443, 9000]
  
  validation {
    condition = alltrue([
      for port in var.waf_custom_ports : port > 0 && port <= 65535
    ])
    error_message = "All ports must be between 1 and 65535."
  }
}

# EKS Standard Profile Variables
variable "eks_cluster_name" {
  description = "Name of the EKS cluster (if applicable)"
  type        = string
  default     = ""
}

# Cross-account sharing configuration (for prefix lists)
variable "share_prefix_lists_with_accounts" {
  description = "List of AWS account IDs to share prefix lists with"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for account in var.share_prefix_lists_with_accounts : can(regex("^[0-9]{12}$", account))
    ])
    error_message = "All account IDs must be 12-digit numbers."
  }
}