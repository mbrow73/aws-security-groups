# Security Group Module Variables

variable "security_group_config" {
  description = "Security group configuration from YAML"
  type = object({
    name        = string
    description = string
    tags        = optional(map(string), {})
    ingress = optional(list(object({
      from_port        = number
      to_port          = number
      protocol         = string
      cidr_blocks      = optional(list(string))
      ipv6_cidr_blocks = optional(list(string))
      prefix_list_ids  = optional(list(string))
      security_groups  = optional(list(string))
      self             = optional(bool)
      description      = optional(string, "Managed by sg-platform")
    })), [])
    egress = optional(list(object({
      from_port        = number
      to_port          = number
      protocol         = string
      cidr_blocks      = optional(list(string))
      ipv6_cidr_blocks = optional(list(string))
      prefix_list_ids  = optional(list(string))
      security_groups  = optional(list(string))
      self             = optional(bool)
      description      = optional(string, "Managed by sg-platform")
    })), [])
  })

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]$", var.security_group_config.name))
    error_message = "SG name: lowercase alphanumeric + hyphens, must start/end with alphanumeric."
  }
}

variable "vpc_id" {
  description = "VPC ID where the security group will be created"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID for tagging"
  type        = string
}

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags from account-level config (merged with corporate mandatory tags)"
  type        = map(string)
  default     = {}
}

variable "security_group_mappings" {
  description = "Map of SG names to IDs for resolving cross-references"
  type        = map(string)
  default     = {}
}

variable "prefix_list_mappings" {
  description = "Map of prefix list names to IDs for resolving references"
  type        = map(string)
  default     = {}
}
