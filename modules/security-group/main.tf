# Security Group Module — creates one SG + rules from YAML config

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
  tags = merge(
    {
      "<company>-app-env"             = var.environment
      "<company>-data-classification" = "internal"
      "<company>-app-carid"           = "600001725"
      "<company>-ops-supportgroup"    = "Security_Operations_Support"
      "<company>-app-supportgroup"    = "Security_Operations_Support"
      "<company>-provisioner-repo"    = "placeholder"
      "<company>-iam-access-control"  = "netsec"
      "<company>-provisioner-workspace" = "600001725-${var.environment}-sg-${var.account_id}"
      Account                         = var.account_id
    },
    var.tags,
    var.security_group_config.tags
  )
}

# --- Security Group ---

resource "aws_security_group" "this" {
  name_prefix = "${var.security_group_config.name}-"
  description = var.security_group_config.description
  vpc_id      = var.vpc_id

  tags = merge(local.tags, {
    Name = var.security_group_config.name
  })

  lifecycle {
    create_before_destroy = true
  }
}

# --- Ingress Rules ---

resource "aws_vpc_security_group_ingress_rule" "this" {
  count = length(var.security_group_config.ingress)

  security_group_id = aws_security_group.this.id
  ip_protocol       = var.security_group_config.ingress[count.index].protocol
  from_port         = var.security_group_config.ingress[count.index].from_port
  to_port           = var.security_group_config.ingress[count.index].to_port
  description       = var.security_group_config.ingress[count.index].description

  # Exactly one source type per rule
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
      ? aws_security_group.this.id
      : null
  )
}

# --- Egress Rules ---

resource "aws_vpc_security_group_egress_rule" "this" {
  count = length(var.security_group_config.egress)

  security_group_id = aws_security_group.this.id
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
      ? aws_security_group.this.id
      : null
  )
}
