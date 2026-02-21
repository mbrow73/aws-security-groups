# AWS Security Group Platform - Account Module Variables

variable "yaml_file" {
  description = "Path to the security-groups.yaml file"
  type        = string
  default     = ""
  
  validation {
    condition = var.yaml_file == "" || can(regex(".*\\.ya?ml$", var.yaml_file))
    error_message = "YAML file must have .yaml or .yml extension."
  }
}

variable "validate_account_id" {
  description = "Whether to validate that we're deploying to the correct AWS account"
  type        = bool
  default     = true
}

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# Advanced configuration options

variable "enable_detailed_monitoring" {
  description = "Whether to enable detailed monitoring for security groups"
  type        = bool
  default     = false
}

variable "create_flow_logs" {
  description = "Whether to create VPC flow logs for security analysis"
  type        = bool
  default     = false
}

variable "flow_logs_retention_days" {
  description = "CloudWatch Logs retention period for VPC flow logs"
  type        = number
  default     = 30
  
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.flow_logs_retention_days)
    error_message = "Flow logs retention must be a valid CloudWatch Logs retention period."
  }
}

variable "enable_security_insights" {
  description = "Whether to enable AWS VPC Security Group Insights"
  type        = bool
  default     = false
}

variable "compliance_mode" {
  description = "Compliance mode for additional validation and tagging"
  type        = string
  default     = "none"
  
  validation {
    condition = contains(["none", "sox", "pci", "hipaa", "iso27001"], var.compliance_mode)
    error_message = "Compliance mode must be one of: none, sox, pci, hipaa, iso27001."
  }
}

# Override configurations

variable "guardrails_override" {
  description = "Override specific guardrails rules (use with caution)"
  type = object({
    allow_0_0_0_0_ingress = optional(bool, false)
    allow_management_ports = optional(bool, false)
    skip_naming_validation = optional(bool, false)
  })
  default = {}
}

variable "custom_prefix_lists" {
  description = "Additional prefix lists to make available for reference"
  type        = map(string)
  default     = {}
}

variable "enable_cross_account_references" {
  description = "Whether to enable cross-account security group references"
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

# Terraform Cloud / Backend Configuration

variable "workspace_tags" {
  description = "Tags to apply to the Terraform Cloud workspace"
  type        = map(string)
  default     = {}
}

variable "auto_apply" {
  description = "Whether Terraform Cloud should auto-apply approved plans"
  type        = bool
  default     = false
}

# Notification and monitoring

variable "notification_webhook_url" {
  description = "Webhook URL for sending deployment notifications (Slack, Teams, etc.)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_cost_monitoring" {
  description = "Whether to enable cost monitoring for resources"
  type        = bool
  default     = false
}

# Backup and disaster recovery

variable "create_backup_snapshots" {
  description = "Whether to create backup snapshots of security group configurations"
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = "Number of days to retain security group backups"
  type        = number
  default     = 90
  
  validation {
    condition = var.backup_retention_days >= 1 && var.backup_retention_days <= 365
    error_message = "Backup retention days must be between 1 and 365."
  }
}

# Performance and scaling

variable "batch_size" {
  description = "Batch size for creating security group rules (helps avoid rate limits)"
  type        = number
  default     = 50
  
  validation {
    condition = var.batch_size >= 1 && var.batch_size <= 100
    error_message = "Batch size must be between 1 and 100."
  }
}

variable "enable_parallel_creation" {
  description = "Whether to enable parallel creation of security groups"
  type        = bool
  default     = true
}

# Testing and validation

variable "dry_run" {
  description = "Whether to run in dry-run mode (plan only, no apply)"
  type        = bool
  default     = false
}

variable "validation_timeout" {
  description = "Timeout in seconds for YAML validation and rule processing"
  type        = number
  default     = 300
  
  validation {
    condition = var.validation_timeout >= 30 && var.validation_timeout <= 3600
    error_message = "Validation timeout must be between 30 and 3600 seconds."
  }
}