# Root Configuration — SG Self-Service Platform
#
# Each TFE workspace sets `account_id` via a variable set.
# This root config reads the corresponding account YAML and
# calls the account module to create team security groups.
#
# Workspace scoping: TFE workspace sg-<account_id> only processes
# accounts/<account_id>/security-groups.yaml via the account_id variable.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "account_id" {
  description = "12-digit AWS account ID — set by TFE variable set per workspace"
  type        = string

  validation {
    condition     = can(regex("^\\d{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID"
  }
}

variable "prefix_list_mappings" {
  description = "Map of prefix list friendly names to AWS prefix list IDs"
  type        = map(string)
  default     = {}
}

module "account" {
  source = "./modules/account"

  yaml_file            = "${path.root}/accounts/${var.account_id}/security-groups.yaml"
  prefix_list_mappings = var.prefix_list_mappings
}

output "security_group_ids" {
  description = "Map of SG name to SG ID for this account"
  value       = module.account.security_group_ids
}

output "account_id" {
  description = "The account ID this workspace manages"
  value       = var.account_id
}
