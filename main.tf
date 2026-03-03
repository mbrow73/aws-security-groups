# Root Configuration — SG Self-Service Platform
#
# Each TFE workspace is named `sg-<account_id>`. The account ID is
# derived from the workspace name — no variables need to be set.
# Dynamic credentials are scoped per account at workspace creation
# via CloudIaC API.
#
# Workspace scoping: TFE workspace sg-<account_id> only processes
# accounts/<account_id>/security-groups.yaml.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  # Derive account_id from workspace name: "sg-123456789012" → "123456789012"
  account_id = regex("^sg-(\\d{12})$", terraform.workspace)[0]
}

variable "prefix_list_mappings" {
  description = "Map of prefix list friendly names to AWS prefix list IDs"
  type        = map(string)
  default     = {}
}

module "account" {
  source = "./modules/account"

  yaml_file            = "${path.root}/accounts/${local.account_id}/security-groups.yaml"
  prefix_list_mappings = var.prefix_list_mappings
}

output "security_group_ids" {
  description = "Map of SG name to SG ID for this account"
  value       = module.account.security_group_ids
}

output "account_id" {
  description = "The account ID this workspace manages"
  value       = local.account_id
}
