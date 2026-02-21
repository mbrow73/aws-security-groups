# AWS Security Group Platform - Variables

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"  # Change this to your preferred region
  
  validation {
    condition = can(regex("^[a-z0-9-]+$", var.aws_region))
    error_message = "AWS region must be a valid region identifier."
  }
}

variable "environment" {
  description = "Environment name (should match the one in your YAML file)"
  type        = string
  default     = "production"  # Change this to match your environment
  
  validation {
    condition     = contains(["development", "dev", "staging", "stage", "production", "prod"], var.environment)
    error_message = "Environment must be one of: development, dev, staging, stage, production, prod."
  }
}

variable "additional_tags" {
  description = "Additional tags to apply to all resources (beyond those in YAML)"
  type        = map(string)
  default     = {}
  
  # Example:
  # default = {
  #   CostCenter = "engineering"
  #   Project    = "security-migration"
  #   Owner      = "platform-team"
  # }
}

# Advanced configuration (usually don't need to change these)

variable "enable_monitoring" {
  description = "Enable additional monitoring and insights"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Create VPC flow logs for security analysis"
  type        = bool
  default     = false
}

variable "compliance_mode" {
  description = "Enable compliance-specific validations and tagging"
  type        = string
  default     = "none"
  
  validation {
    condition     = contains(["none", "sox", "pci", "hipaa", "iso27001"], var.compliance_mode)
    error_message = "Compliance mode must be one of: none, sox, pci, hipaa, iso27001."
  }
}