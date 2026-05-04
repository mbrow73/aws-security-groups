variable "security_groups" {
  description = "Map of security group name to config (pre-filtered by region from root module)"
  type        = any
}

variable "account_id" {
  description = "AWS Account ID for tagging"
  type        = string
}

variable "tags" {
  description = "Pre-computed tags (platform + corporate mandatory + account extras)"
  type        = map(string)
  default     = {}
}

variable "prefix_list_mappings" {
  description = "Map of prefix list names to IDs for this specific region (static/external mappings must already be region-resolved before reaching the account module)"
  type        = map(string)
  default     = {}
}

variable "shared_prefix_lists" {
  description = "Map of shared repo-managed prefix lists to create in this account/region"
  type        = any
  default     = {}
}

variable "platform_security_groups" {
  description = "Map of platform built-in security groups to create automatically in this account/region"
  type        = any
  default     = {}
}
