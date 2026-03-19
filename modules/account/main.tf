# Account Module — creates team SGs for a single region
#
# Receives pre-filtered security groups from the root module (grouped by region).
# The root module handles YAML parsing, region routing, and tag computation.
#
# Baselines are deployed separately via terraform-aws-eks-baseline-sgs module.
# This module handles team-requested custom security groups only.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# VPC — auto-discovered per region (each region has its own VPC)
data "aws_vpc" "discovered" {
  filter {
    name   = "state"
    values = ["available"]
  }
}

# Team security groups
module "security_groups" {
  for_each = var.security_groups
  source   = "../security-group"

  security_group_config = merge(each.value, { name = each.key })
  vpc_id                = lookup(each.value, "vpc_id", data.aws_vpc.discovered.id)
  account_id            = var.account_id
  tags                  = var.tags
  prefix_list_mappings  = var.prefix_list_mappings
}
