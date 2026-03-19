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

# --- Ingress Rules ---

resource "aws_vpc_security_group_ingress_rule" "this" {
  count = length(var.security_group_config.ingress)

  security_group_id = var.security_group_id
  ip_protocol       = var.security_group_config.ingress[count.index].protocol
  from_port         = var.security_group_config.ingress[count.index].from_port
  to_port           = var.security_group_config.ingress[count.index].to_port
  description       = var.security_group_config.ingress[count.index].description

  cidr_ipv4 = (
    var.security_group_config.ingress[count.index].cidr_blocks != null
    ? var.security_group_config.ingress[count.index].cidr_blocks[0]
    : null
  )

  cidr_ipv6 = (
    var.security_group_config.ingress[count.index].ipv6_cidr_blocks != null
    ? var.security_group_config.ingress[count.index].ipv6_cidr_blocks[0]
    : null
  )

  prefix_list_id = (
    var.security_group_config.ingress[count.index].prefix_list_ids != null
    ? lookup(
        var.prefix_list_mappings,
        var.security_group_config.ingress[count.index].prefix_list_ids[0],
        var.security_group_config.ingress[count.index].prefix_list_ids[0]
      )
    : null
  )

  referenced_security_group_id = (
    var.security_group_config.ingress[count.index].security_groups != null
    ? lookup(
        var.security_group_mappings,
        var.security_group_config.ingress[count.index].security_groups[0],
        var.security_group_config.ingress[count.index].security_groups[0]
      )
    : var.security_group_config.ingress[count.index].self == true
      ? var.security_group_id
      : null
  )
}

# --- Egress Rules ---

resource "aws_vpc_security_group_egress_rule" "this" {
  count = length(var.security_group_config.egress)

  security_group_id = var.security_group_id
  ip_protocol       = var.security_group_config.egress[count.index].protocol
  from_port         = var.security_group_config.egress[count.index].from_port
  to_port           = var.security_group_config.egress[count.index].to_port
  description       = var.security_group_config.egress[count.index].description

  cidr_ipv4 = (
    var.security_group_config.egress[count.index].cidr_blocks != null
    ? var.security_group_config.egress[count.index].cidr_blocks[0]
    : null
  )

  cidr_ipv6 = (
    var.security_group_config.egress[count.index].ipv6_cidr_blocks != null
    ? var.security_group_config.egress[count.index].ipv6_cidr_blocks[0]
    : null
  )

  prefix_list_id = (
    var.security_group_config.egress[count.index].prefix_list_ids != null
    ? lookup(
        var.prefix_list_mappings,
        var.security_group_config.egress[count.index].prefix_list_ids[0],
        var.security_group_config.egress[count.index].prefix_list_ids[0]
      )
    : null
  )

  referenced_security_group_id = (
    var.security_group_config.egress[count.index].security_groups != null
    ? lookup(
        var.security_group_mappings,
        var.security_group_config.egress[count.index].security_groups[0],
        var.security_group_config.egress[count.index].security_groups[0]
      )
    : var.security_group_config.egress[count.index].self == true
      ? var.security_group_id
      : null
  )
}
