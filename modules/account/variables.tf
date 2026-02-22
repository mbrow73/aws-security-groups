variable "yaml_file" {
  description = "Path to the account's security-groups.yaml"
  type        = string
}

variable "prefix_list_mappings" {
  description = "Map of prefix list names to IDs"
  type        = map(string)
  default     = {}
}
