# Security Group Rules Module — creates rules for an existing SG
#
# The SG itself is created by the account module. This module only
# manages ingress/egress rules, with access to the full name→ID
# mapping for cross-SG references.

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
  ingress_rules = {
    for rule in var.security_group_config.ingress : join("|", [
      lower(rule.protocol),
      tostring(rule.from_port),
      tostring(rule.to_port),
      try(rule.cidr_blocks[0], ""),
      try(rule.ipv6_cidr_blocks[0], ""),
      try(rule.prefix_list_ids[0], ""),
      try(rule.security_groups[0], ""),
      tostring(try(rule.self, false)),
    ]) => rule
  }

  egress_rules = {
    for rule in var.security_group_config.egress : join("|", [
      lower(rule.protocol),
      tostring(rule.from_port),
      tostring(rule.to_port),
      try(rule.cidr_blocks[0], ""),
      try(rule.ipv6_cidr_blocks[0], ""),
      try(rule.prefix_list_ids[0], ""),
      try(rule.security_groups[0], ""),
      tostring(try(rule.self, false)),
    ]) => rule
  }
}

# --- Ingress Rules ---

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.ingress_rules

  security_group_id = var.security_group_id
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  description       = each.value.description

  cidr_ipv4 = (
    each.value.cidr_blocks != null
    ? each.value.cidr_blocks[0]
    : null
  )

  cidr_ipv6 = (
    each.value.ipv6_cidr_blocks != null
    ? each.value.ipv6_cidr_blocks[0]
    : null
  )

  prefix_list_id = (
    each.value.prefix_list_ids != null
    ? lookup(
      var.prefix_list_mappings,
      each.value.prefix_list_ids[0],
      each.value.prefix_list_ids[0]
    )
    : null
  )

  referenced_security_group_id = (
    each.value.security_groups != null
    ? lookup(
      var.security_group_mappings,
      each.value.security_groups[0],
      each.value.security_groups[0]
    )
    : each.value.self == true
    ? var.security_group_id
    : null
  )

  tags = var.tags
}

# --- Egress Rules ---

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = local.egress_rules

  security_group_id = var.security_group_id
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  description       = each.value.description

  cidr_ipv4 = (
    each.value.cidr_blocks != null
    ? each.value.cidr_blocks[0]
    : null
  )

  cidr_ipv6 = (
    each.value.ipv6_cidr_blocks != null
    ? each.value.ipv6_cidr_blocks[0]
    : null
  )

  prefix_list_id = (
    each.value.prefix_list_ids != null
    ? lookup(
      var.prefix_list_mappings,
      each.value.prefix_list_ids[0],
      each.value.prefix_list_ids[0]
    )
    : null
  )

  referenced_security_group_id = (
    each.value.security_groups != null
    ? lookup(
      var.security_group_mappings,
      each.value.security_groups[0],
      each.value.security_groups[0]
    )
    : each.value.self == true
    ? var.security_group_id
    : null
  )

  tags = var.tags
}
