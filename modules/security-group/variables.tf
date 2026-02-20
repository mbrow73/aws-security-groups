# AWS Security Group Platform - Security Group Module Variables

variable "security_group_config" {
  description = "Security group configuration parsed from YAML"
  type = object({
    name        = string
    description = string
    type        = optional(string, "custom")
    tags        = optional(map(string), {})
    ingress     = optional(list(object({
      from_port               = number
      to_port                 = number
      protocol                = string
      cidr_blocks            = optional(list(string))
      ipv6_cidr_blocks       = optional(list(string))
      prefix_list_ids        = optional(list(string))
      source_security_groups = optional(list(string))
      security_groups        = optional(list(string))  # Alternative name
      self                   = optional(bool)
      description            = optional(string)
    })), [])
    egress = optional(list(object({
      from_port               = number
      to_port                 = number
      protocol                = string
      cidr_blocks            = optional(list(string))
      ipv6_cidr_blocks       = optional(list(string))
      prefix_list_ids        = optional(list(string))
      source_security_groups = optional(list(string))
      security_groups        = optional(list(string))  # Alternative name
      self                   = optional(bool)
      description            = optional(string)
    })), [])
  })

  validation {
    condition = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.security_group_config.name))
    error_message = "Security group name must follow naming convention: lowercase, alphanumeric, hyphens allowed, must start and end with alphanumeric."
  }

  validation {
    condition = length(var.security_group_config.name) <= 63
    error_message = "Security group name must be 63 characters or less."
  }

  validation {
    condition = contains([
      "eks-nodes", "nlb", "alb", "web", "database", "monitoring", "custom"
    ], var.security_group_config.type)
    error_message = "Security group type must be one of: eks-nodes, nlb, alb, web, database, monitoring, custom."
  }
}

variable "vpc_id" {
  description = "VPC ID where the security group will be created"
  type        = string
  
  validation {
    condition = can(regex("^vpc-[a-f0-9]{8}([a-f0-9]{9})?$", var.vpc_id))
    error_message = "VPC ID must be a valid AWS VPC ID format."
  }
}

variable "account_id" {
  description = "AWS Account ID for tagging and reference"
  type        = string
  
  validation {
    condition = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Account ID must be a 12-digit number."
  }
}

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = ""
  
  validation {
    condition = var.environment == "" || contains(["production", "staging", "development", "test"], var.environment)
    error_message = "Environment must be one of: production, staging, development, test, or empty string."
  }
}

variable "tags" {
  description = "Additional tags to apply to the security group"
  type        = map(string)
  default     = {}
}

# Mapping variables for resolving references

variable "security_group_mappings" {
  description = "Map of security group names to IDs for resolving references"
  type        = map(string)
  default     = {}
}

variable "prefix_list_mappings" {
  description = "Map of prefix list names to IDs for resolving references"
  type        = map(string)
  default     = {}
}

variable "baseline_security_groups" {
  description = "Map of baseline security group names to IDs"
  type        = map(string)
  default     = {}
}

variable "baseline_prefix_lists" {
  description = "Map of baseline prefix list names to IDs"
  type        = map(string)
  default     = {}
}

# Flow logs configuration

variable "enable_flow_logs" {
  description = "Whether to enable VPC Flow Logs for security group analysis"
  type        = bool
  default     = false
}

variable "flow_logs_role_arn" {
  description = "IAM role ARN for VPC Flow Logs (required if enable_flow_logs is true)"
  type        = string
  default     = null
}

variable "flow_logs_destination_arn" {
  description = "Destination ARN for VPC Flow Logs (CloudWatch Logs or S3)"
  type        = string
  default     = null
}

# Compliance and validation settings

variable "require_description_for_rules" {
  description = "Whether to require descriptions for all security group rules"
  type        = bool
  default     = true
}

variable "compliance_mode" {
  description = "Compliance mode for additional validation (none, sox, pci, hipaa)"
  type        = string
  default     = "none"
  
  validation {
    condition = contains(["none", "sox", "pci", "hipaa"], var.compliance_mode)
    error_message = "Compliance mode must be one of: none, sox, pci, hipaa."
  }
}

variable "max_ingress_rules" {
  description = "Maximum number of ingress rules allowed per security group"
  type        = number
  default     = 60
  
  validation {
    condition = var.max_ingress_rules > 0 && var.max_ingress_rules <= 120
    error_message = "Max ingress rules must be between 1 and 120."
  }
}

variable "max_egress_rules" {
  description = "Maximum number of egress rules allowed per security group"
  type        = number
  default     = 60
  
  validation {
    condition = var.max_egress_rules > 0 && var.max_egress_rules <= 120
    error_message = "Max egress rules must be between 1 and 120."
  }
}

# Advanced configuration

variable "enable_security_group_insights" {
  description = "Whether to enable detailed security group rule analysis"
  type        = bool
  default     = false
}

variable "custom_type_configurations" {
  description = "Custom configurations for security group types"
  type = map(object({
    predefined_egress = optional(list(object({
      from_port   = number
      to_port     = number
      protocol    = string
      cidr_blocks = optional(list(string))
      description = string
    })), [])
    self_referencing = optional(bool, false)
    default_egress   = optional(bool, true)
  }))
  default = {}
}

variable "rule_priority_enforcement" {
  description = "Whether to enforce rule priority and ordering"
  type        = bool
  default     = false
}

variable "enable_rule_deduplication" {
  description = "Whether to automatically deduplicate identical rules"
  type        = bool
  default     = true
}

# Network configuration

variable "vpc_cidr" {
  description = "VPC CIDR block for internal rules optimization"
  type        = string
  default     = null
}

variable "subnet_cidrs" {
  description = "Map of subnet types to CIDR blocks for rule optimization"
  type        = map(list(string))
  default     = {}
}

# Monitoring and alerting

variable "enable_rule_monitoring" {
  description = "Whether to enable monitoring for security group rule usage"
  type        = bool
  default     = false
}

variable "monitoring_tags" {
  description = "Additional tags for monitoring resources"
  type        = map(string)
  default     = {}
}

# Backup and disaster recovery

variable "enable_backup_rules" {
  description = "Whether to create backup copies of security group rules"
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = "Number of days to retain security group rule backups"
  type        = number
  default     = 30
}

# Cross-region and cross-account considerations

variable "enable_cross_region_references" {
  description = "Whether to enable cross-region security group references"
  type        = bool
  default     = false
}

variable "trusted_accounts" {
  description = "List of AWS account IDs trusted for cross-account references"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for account in var.trusted_accounts : can(regex("^[0-9]{12}$", account))
    ])
    error_message = "All trusted account IDs must be 12-digit numbers."
  }
}