# AWS Security Group Platform - Example Variables

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition = can(regex("^[a-z0-9-]+$", var.aws_region))
    error_message = "AWS region must be a valid region identifier."
  }
}

variable "environment" {
  description = "Environment name (should match the one in security-groups.yaml)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "dev", "staging", "stage", "production", "prod"], var.environment)
    error_message = "Environment must be one of: development, dev, staging, stage, production, prod."
  }
}

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default = {
    Example = "true"
    Purpose = "demonstration"
  }
}

# Example advanced configuration options

variable "enable_monitoring" {
  description = "Enable additional monitoring and insights"
  type        = bool
  default     = true  # Enabled in example to show functionality
}

variable "enable_flow_logs" {
  description = "Create VPC flow logs for security analysis"
  type        = bool
  default     = false  # Disabled to avoid costs in example
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

# Example: Organization-specific variables
variable "cost_center" {
  description = "Cost center for billing allocation"
  type        = string
  default     = "platform-engineering"
}

variable "business_unit" {
  description = "Business unit owning these resources"
  type        = string
  default     = "infrastructure"
}