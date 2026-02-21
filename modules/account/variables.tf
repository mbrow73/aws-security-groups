# AWS Security Group Platform - Account Module Variables

variable "yaml_file" {
  description = "Path to the security-groups.yaml file"
  type        = string
  
  validation {
    condition = can(regex(".*\\.ya?ml$", var.yaml_file))
    error_message = "YAML file must have .yaml or .yml extension."
  }
}