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
# This module handles team-requested custom security groups plus repo-managed
# shared prefix lists.

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
# Step 1: Create SG shells and shared prefix lists for this region
# ---------------------------------------------------------------------------

locals {
  automatic_platform_security_groups = {
    for name, sg in var.platform_security_groups :
    name => sg
    if lookup(sg, "provision", "manual") == "automatic"
  }
}

resource "aws_security_group" "platform_builtin" {
  for_each = local.automatic_platform_security_groups

  name_prefix = "${each.key}-"
  description = each.value.description
  vpc_id      = data.aws_vpc.discovered.id

  tags = merge(var.tags, {
    Name        = each.key
    Type        = "platform-builtin"
    ManagedBy   = "sg-platform"
    ReviewClass = lookup(each.value, "review_class", "platform_builtin")
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "platform_builtin_vpc_cidr_ingress" {
  for_each = {
    for name, sg in local.automatic_platform_security_groups :
    name => sg
    if lookup(sg, "source", null) == "vpc_cidr"
  }

  type              = "ingress"
  security_group_id = aws_security_group.platform_builtin[each.key].id
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = [data.aws_vpc.discovered.cidr_block]
  description       = "Platform-managed ingress from discovered VPC CIDR"
}

resource "aws_security_group" "this" {
  for_each = var.security_groups

  name_prefix = "${lookup(each.value, "_logical_name", each.key)}-"
  description = each.value.description
  vpc_id      = lookup(each.value, "vpc_id", data.aws_vpc.discovered.id)

  tags = merge(var.tags, lookup(each.value, "tags", {}), {
    Name = lookup(each.value, "_logical_name", each.key)
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_ec2_managed_prefix_list" "shared" {
  for_each = var.shared_prefix_lists

  name           = each.key
  address_family = lookup(each.value, "address_family", "IPv4")
  max_entries    = lookup(each.value, "max_entries", length(lookup(each.value, "entries", [])))

  tags = merge(var.tags, lookup(each.value, "tags", {}), {
    Name = each.key
    Type = "shared-prefix-list"
  })
}

locals {
  shared_prefix_list_entries = merge(
    {},
    [
      for pl_name, pl in var.shared_prefix_lists : {
        for idx, entry in lookup(pl, "entries", []) :
        "${pl_name}:${idx}" => {
          prefix_list_name = pl_name
          cidr             = entry.cidr
          description      = lookup(entry, "description", null)
        }
      }
    ]...
  )
}

resource "aws_ec2_managed_prefix_list_entry" "shared" {
  for_each = local.shared_prefix_list_entries

  cidr           = each.value.cidr
  description    = each.value.description
  prefix_list_id = aws_ec2_managed_prefix_list.shared[each.value.prefix_list_name].id
}

# ---------------------------------------------------------------------------
# Name→ID mappings and reference resolution
# ---------------------------------------------------------------------------

locals {
  security_group_mappings = merge(
    {
      for name, sg in aws_security_group.platform_builtin :
      name => sg.id
    },
    {
      for name, sg in aws_security_group.this :
      name => sg.id
    },
    {
      for name, sg in aws_security_group.this :
      lookup(var.security_groups[name], "_logical_name", name) => sg.id
    }
  )

  # Baseline refs actually used by this region's SG rules.
  baseline_refs_used = distinct(flatten([
    for sg_name, sg in var.security_groups : concat(
      [for rule in lookup(sg, "ingress", []) : lookup(rule, "baseline_ref", null) if lookup(rule, "baseline_ref", null) != null],
      [for rule in lookup(sg, "egress", []) : lookup(rule, "baseline_ref", null) if lookup(rule, "baseline_ref", null) != null]
    )
  ]))

  # Only look up baseline refs that are both allowed and actually referenced.
  baseline_refs_to_lookup = toset([
    for ref in local.baseline_refs_used : ref
    if contains(var.baseline_ref_allowlist, ref)
  ])

  baseline_sg_mappings = {
    for name, sg in data.aws_security_group.baseline :
    name => sg.id
  }

  shared_prefix_list_mappings = {
    for name, pl in aws_ec2_managed_prefix_list.shared :
    name => pl.id
  }

  # Decoupled model: shared/self-service prefix lists are owned by this repo.
  # Optional static mappings still work, but baseline/known prefix list lookup is no longer part of the main path.
  all_prefix_list_mappings = merge(
    var.prefix_list_mappings,
    local.shared_prefix_list_mappings,
  )
}

# ---------------------------------------------------------------------------
# External lookups — only for baseline SG refs
# ---------------------------------------------------------------------------

data "aws_security_group" "baseline" {
  for_each = local.baseline_refs_to_lookup

  filter {
    name   = "tag:Name"
    values = ["baseline-${each.value}"]
  }

  filter {
    name   = "tag:Type"
    values = ["baseline"]
  }

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.discovered.id]
  }
}

# ---------------------------------------------------------------------------
# Step 2: Create rules, passing the full SG name→ID mapping
# ---------------------------------------------------------------------------

module "security_group_rules" {
  for_each = var.security_groups
  source   = "../security-group-rules"

  security_group_id       = aws_security_group.this[each.key].id
  security_group_config   = merge(each.value, { name = lookup(each.value, "_logical_name", each.key) })
  security_group_mappings = local.security_group_mappings
  prefix_list_mappings    = local.all_prefix_list_mappings
  baseline_sg_mappings    = local.baseline_sg_mappings
  tags                    = var.tags
}
