# Account Module — creates team SGs for a single region
#
# Receives pre-filtered security groups from the root module (grouped by region).
# The root module handles YAML parsing, region routing, and tag computation.
#
# Two-pass approach for cross-SG references:
#   1. Create all SG shells (empty security groups) to establish name→ID mapping
#   2. Pass mapping to SG rule module so rules can reference SGs by name
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

# ---------------------------------------------------------------------------
# Step 1: Create SG shells to establish name→ID mappings
# ---------------------------------------------------------------------------

resource "aws_security_group" "this" {
  for_each = var.security_groups

  name_prefix = "${each.key}-"
  description = each.value.description
  vpc_id      = lookup(each.value, "vpc_id", data.aws_vpc.discovered.id)

  tags = merge(var.tags, lookup(each.value, "tags", {}), {
    Name = each.key
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Name→ID mapping for cross-SG references
locals {
  security_group_mappings = {
    for name, sg in aws_security_group.this :
    name => sg.id
  }
}

# ---------------------------------------------------------------------------
# Step 2: Create rules, passing the full SG name→ID mapping
# ---------------------------------------------------------------------------

module "security_group_rules" {
  for_each = var.security_groups
  source   = "../security-group-rules"

  security_group_id      = aws_security_group.this[each.key].id
  security_group_config  = merge(each.value, { name = each.key })
  security_group_mappings = local.security_group_mappings
  prefix_list_mappings   = var.prefix_list_mappings
}
