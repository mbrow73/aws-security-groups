# Account Module — reads security-groups.yaml and creates team SGs
#
# Baselines are deployed separately via terraform-aws-eks-baseline-sgs module.
# This module handles team-requested custom security groups only.
#
# Corporate mandatory tags are computed automatically from account-level
# fields (environment, carid) — requestors never specify tags manually.

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
  environment = lookup(local.config, "environment", "unknown")
  carid       = tostring(local.config.carid)

  # Corporate mandatory tags — computed automatically, not requestor-specified
  corporate_mandatory_tags = {
    "<company>-app-env"                = local.environment
    "<company>-data-classification"    = "internal"
    "<company>-app-carid"              = local.carid
    "<company>-ops-supportgroup"       = "Security_Operations_Support"
    "<company>-app-supportgroup"       = "Security_Operations_Support"
    "<company>-provisioner-repo"       = "placeholder"
    "<company>-iam-access-control"     = "netsec"
    "<company>-provisioner-workspace"  = "${local.carid}-${local.environment}-sg-${local.account_id}"
  }

  # Platform-managed tags
  platform_tags = {
    ManagedBy   = "sg-platform"
    Account     = local.account_id
    Environment = local.environment
    Repository  = "aws-security-groups"
  }

  # All tags merged: platform + corporate mandatory + any account-level extras
  common_tags = merge(
    local.platform_tags,
    local.corporate_mandatory_tags,
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
  tags                  = local.common_tags
  prefix_list_mappings  = var.prefix_list_mappings
}
