# AWS Security Group Platform - VPC Discovery Module Variables

variable "vpc_id" {
  description = "VPC ID to use. Set to 'auto' for automatic discovery."
  type        = string
  default     = "auto"
  
  validation {
    condition = var.vpc_id == "auto" || can(regex("^vpc-[a-f0-9]{8}([a-f0-9]{9})?$", var.vpc_id))
    error_message = "VPC ID must be 'auto' or a valid VPC ID format (vpc-xxxxxxxx)."
  }
}

variable "account_id" {
  description = "AWS Account ID for context and validation"
  type        = string
  
  validation {
    condition = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Account ID must be a 12-digit number."
  }
}

variable "region" {
  description = "AWS region for discovery"
  type        = string
  default     = ""  # Will use provider default if not specified
}

# VPC Discovery Configuration

variable "vpc_filter_tags" {
  description = "Tags to filter VPCs during discovery"
  type        = map(string)
  default     = {}
  
  # Common example filters:
  # {
  #   Environment = "production"
  #   ManagedBy   = "terraform"
  # }
}

variable "priority_tags" {
  description = "Tag keys that indicate VPC priority for auto-selection"
  type        = list(string)
  default     = ["Main", "Primary", "Default", "Production"]
}

variable "exclude_default_vpc" {
  description = "Whether to exclude the default VPC from auto-selection"
  type        = bool
  default     = true
}

variable "require_internet_access" {
  description = "Whether the selected VPC must have internet access (IGW or NAT)"
  type        = bool
  default     = false
}

variable "require_private_subnets" {
  description = "Whether the selected VPC must have private subnets"
  type        = bool
  default     = false
}

variable "require_public_subnets" {
  description = "Whether the selected VPC must have public subnets"
  type        = bool
  default     = false
}

variable "min_availability_zones" {
  description = "Minimum number of availability zones required"
  type        = number
  default     = 1
  
  validation {
    condition = var.min_availability_zones >= 1 && var.min_availability_zones <= 6
    error_message = "Minimum availability zones must be between 1 and 6."
  }
}

# Subnet Discovery Configuration

variable "subnet_filter_tags" {
  description = "Tags to filter subnets during discovery"
  type        = map(string)
  default     = {}
}

variable "subnet_naming_patterns" {
  description = "Regex patterns for categorizing subnets by name"
  type = object({
    private  = optional(string, ".*private.*")
    public   = optional(string, ".*public.*")
    database = optional(string, ".*database.*|.*db.*|.*rds.*")
    internal = optional(string, ".*internal.*")
  })
  default = {}
}

variable "subnet_type_tags" {
  description = "Tag keys that indicate subnet type"
  type        = list(string)
  default     = ["Type", "type", "SubnetType", "subnet-type"]
}

# Security Group Discovery Configuration

variable "existing_sg_filter_tags" {
  description = "Tags to filter existing security groups during discovery"
  type        = map(string)
  default     = {}
}

variable "include_baseline_sgs" {
  description = "Whether to include baseline security groups in discovery"
  type        = bool
  default     = true
}

variable "baseline_sg_patterns" {
  description = "Name patterns to identify baseline security groups"
  type        = list(string)
  default     = ["baseline-*", "common-*", "shared-*"]
}

# Network Analysis Configuration

variable "analyze_routing" {
  description = "Whether to analyze route tables for better subnet categorization"
  type        = bool
  default     = true
}

variable "discover_vpc_endpoints" {
  description = "Whether to discover existing VPC endpoints"
  type        = bool
  default     = true
}

variable "discover_nat_gateways" {
  description = "Whether to discover NAT gateways"
  type        = bool
  default     = true
}

variable "discover_network_acls" {
  description = "Whether to discover Network ACLs"
  type        = bool
  default     = false
}

# Validation Configuration

variable "strict_validation" {
  description = "Whether to use strict validation (fail on warnings)"
  type        = bool
  default     = false
}

variable "validation_rules" {
  description = "Custom validation rules for VPC selection"
  type = object({
    min_subnets           = optional(number, 2)
    max_subnets           = optional(number, 50)
    require_multi_az      = optional(bool, false)
    require_vpc_endpoints = optional(bool, false)
    allowed_cidr_ranges   = optional(list(string), [])
    blocked_cidr_ranges   = optional(list(string), [])
  })
  default = {}
}

# Output Configuration

variable "include_sensitive_data" {
  description = "Whether to include potentially sensitive data in outputs"
  type        = bool
  default     = false
}

variable "detailed_analysis" {
  description = "Whether to perform detailed network analysis"
  type        = bool
  default     = true
}

variable "export_to_file" {
  description = "Whether to export discovery results to a local file"
  type        = bool
  default     = false
}

variable "export_file_path" {
  description = "Path for exporting discovery results"
  type        = string
  default     = "./vpc-discovery-results.json"
}

# Advanced Configuration

variable "custom_discovery_rules" {
  description = "Custom rules for VPC and subnet discovery"
  type = map(object({
    priority    = number
    condition   = string
    description = string
  }))
  default = {}
}

variable "cache_discovery_results" {
  description = "Whether to cache discovery results for performance"
  type        = bool
  default     = false
}

variable "cache_ttl_minutes" {
  description = "Cache TTL in minutes for discovery results"
  type        = number
  default     = 60
  
  validation {
    condition = var.cache_ttl_minutes > 0 && var.cache_ttl_minutes <= 1440
    error_message = "Cache TTL must be between 1 and 1440 minutes."
  }
}

# Cross-Account Discovery (for future use)

variable "cross_account_role_arn" {
  description = "IAM role ARN for cross-account VPC discovery"
  type        = string
  default     = null
}

variable "trusted_accounts" {
  description = "List of trusted AWS account IDs for cross-account discovery"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for account in var.trusted_accounts : can(regex("^[0-9]{12}$", account))
    ])
    error_message = "All trusted account IDs must be 12-digit numbers."
  }
}