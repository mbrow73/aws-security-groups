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

# Security Group Configuration Variables

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

variable "common_app_ports" {
  description = "Common application ports for load balancer to application communication"
  type        = list(number)
  default     = [8000, 8080, 8443, 9000, 9443]
  
  validation {
    condition = alltrue([
      for port in var.common_app_ports : port > 0 && port <= 65535
    ])
    error_message = "All ports must be between 1 and 65535."
  }
}

variable "monitoring_ports" {
  description = "Custom monitoring and metrics ports"
  type        = list(number)
  default     = [9091, 9093, 9094, 9113, 9115]
  
  validation {
    condition = alltrue([
      for port in var.monitoring_ports : port > 0 && port <= 65535
    ])
    error_message = "All ports must be between 1 and 65535."
  }
}

# EKS specific configuration

variable "eks_cluster_name" {
  description = "Name of the EKS cluster (if applicable)"
  type        = string
  default     = ""
}

variable "eks_additional_security_groups" {
  description = "Additional security group IDs to associate with EKS cluster"
  type        = list(string)
  default     = []
}

# Database configuration

variable "enable_database_baseline" {
  description = "Whether to create the baseline database security group"
  type        = bool
  default     = true
}

variable "database_ports" {
  description = "Database ports to allow in baseline database security group"
  type = map(object({
    port        = number
    description = string
  }))
  default = {
    mysql = {
      port        = 3306
      description = "MySQL/Aurora"
    }
    postgresql = {
      port        = 5432
      description = "PostgreSQL"
    }
    redis = {
      port        = 6379
      description = "Redis"
    }
    memcached = {
      port        = 11211
      description = "Memcached"
    }
  }
}

# Load balancer configuration

variable "enable_nlb_baseline" {
  description = "Whether to create baseline NLB security groups"
  type        = bool
  default     = true
}

variable "enable_alb_baseline" {
  description = "Whether to create baseline ALB security groups"
  type        = bool
  default     = true
}

# Monitoring configuration

variable "enable_monitoring_baseline" {
  description = "Whether to create baseline monitoring security group"
  type        = bool
  default     = true
}

variable "monitoring_sources" {
  description = "Sources allowed to access monitoring endpoints"
  type = object({
    internal_cidrs     = list(string)
    external_cidrs     = list(string)
    security_group_ids = list(string)
  })
  default = {
    internal_cidrs     = []
    external_cidrs     = []
    security_group_ids = []
  }
}

# Cross-account sharing configuration

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

variable "enable_cross_account_access" {
  description = "Whether to enable cross-account access for security groups"
  type        = bool
  default     = false
}

# Advanced configuration

variable "create_flow_logs" {
  description = "Whether to create VPC Flow Logs for the security groups"
  type        = bool
  default     = false
}

variable "flow_logs_destination" {
  description = "Destination for VPC Flow Logs (cloud-watch-logs or s3)"
  type        = string
  default     = "cloud-watch-logs"
  
  validation {
    condition     = contains(["cloud-watch-logs", "s3"], var.flow_logs_destination)
    error_message = "Flow logs destination must be either 'cloud-watch-logs' or 's3'."
  }
}

variable "enable_security_group_insights" {
  description = "Whether to enable Security Group rule insights and analysis"
  type        = bool
  default     = false
}

# Compliance and governance

variable "compliance_mode" {
  description = "Compliance mode for additional restrictions (none, sox, pci, hipaa)"
  type        = string
  default     = "none"
  
  validation {
    condition     = contains(["none", "sox", "pci", "hipaa"], var.compliance_mode)
    error_message = "Compliance mode must be one of: none, sox, pci, hipaa."
  }
}

variable "require_description_for_rules" {
  description = "Whether to require descriptions for all security group rules"
  type        = bool
  default     = true
}

variable "auto_remediation" {
  description = "Whether to enable auto-remediation for non-compliant rules"
  type        = bool
  default     = false
}