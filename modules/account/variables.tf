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
  description = "Map of prefix list names to IDs"
  type        = map(string)
  default     = {}
}

variable "baseline_ref_allowlist" {
  description = "List of allowed baseline_ref names that can be referenced (e.g. vpc-endpoints)"
  type        = list(string)
  default     = []
}
