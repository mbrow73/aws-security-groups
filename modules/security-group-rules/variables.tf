variable "security_group_id" {
  description = "ID of the existing security group to attach rules to"
  type        = string
}

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
}

variable "security_group_mappings" {
  description = "Map of SG names to IDs for resolving cross-references within the same account/region"
  type        = map(string)
  default     = {}
}

variable "prefix_list_mappings" {
  description = "Map of prefix list names to IDs for resolving references"
  type        = map(string)
  default     = {}
}
