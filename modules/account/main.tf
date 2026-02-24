# Account Module — reads security-groups.yaml and creates team SGs
#
# Baselines are deployed separately via terraform-aws-eks-baseline-sgs module.
# This module handles team-requested custom security groups only.
#
# Note: Cross-references between SGs in the same YAML use raw SG IDs
# or are resolved post-apply. Teams reference external SGs by ID,
# prefix lists by name (resolved via prefix_list_mappings).

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
  config     = yamldecode(file(var.yaml_file))
  account_id = tostring(local.config.account_id)

  common_tags = merge(
    {
      ManagedBy   = "sg-platform"
      Account     = local.account_id
      Environment = lookup(local.config, "environment", "unknown")
      Repository  = "aws-security-groups"
    },
    lookup(local.config, "tags", {})
  )
}

# VPC — either explicit or auto-discovered
data "aws_vpc" "selected" {
  count = lookup(local.config, "vpc_id", "auto") != "auto" ? 1 : 0
  id    = local.config.vpc_id
}

data "aws_vpc" "discovered" {
  count = lookup(local.config, "vpc_id", "auto") == "auto" ? 1 : 0
  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  vpc_id = (
    lookup(local.config, "vpc_id", "auto") != "auto"
    ? data.aws_vpc.selected[0].id
    : data.aws_vpc.discovered[0].id
  )
}

# Team security groups from YAML
module "security_groups" {
  for_each = lookup(local.config, "security_groups", {})
  source   = "../security-group"

  security_group_config = merge(each.value, { name = each.key })
  vpc_id                = lookup(each.value, "vpc_id", local.vpc_id)
  account_id            = local.account_id
  environment           = lookup(local.config, "environment", "")
  tags                  = local.common_tags
  prefix_list_mappings  = var.prefix_list_mappings

  # External SG references only — no self-referencing between SGs in this YAML
  # Teams reference external SGs by ID (e.g., sg-0123abc)
  # Cross-SG references within the same account are handled by Terraform's
  # natural dependency resolution when using actual SG IDs
}
