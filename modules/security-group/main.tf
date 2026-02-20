# AWS Security Group Platform - Reusable Security Group Module
# This module creates security groups from YAML configuration with built-in best practices

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
  # Merge provided tags with standard tags
  standard_tags = {
    ManagedBy    = "sg-platform"
    Module       = "security-group"
    Account      = var.account_id
    Environment  = var.environment
    Repository   = "aws-security-groups"
  }
  
  final_tags = merge(local.standard_tags, var.tags, var.security_group_config.tags)
  
  # Parse security group type for predefined configurations
  sg_type = lookup(var.security_group_config, "type", "custom")
  
  # Type-specific defaults
  type_defaults = {
    "eks-nodes" = {
      predefined_egress = [
        {
          from_port   = 443
          to_port     = 443
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "HTTPS outbound for pulling images and API access"
        },
        {
          from_port   = 53
          to_port     = 53
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "DNS TCP"
        },
        {
          from_port   = 53
          to_port     = 53
          protocol    = "udp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "DNS UDP"
        },
        {
          from_port   = 123
          to_port     = 123
          protocol    = "udp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "NTP"
        }
      ]
      self_referencing = true
    }
    "nlb" = {
      predefined_egress = []
      self_referencing = false
    }
    "web" = {
      predefined_egress = [
        {
          from_port   = 443
          to_port     = 443
          protocol    = "tcp"
          cidr_blocks = ["0.0.0.0/0"]
          description = "HTTPS outbound"
        }
      ]
      self_referencing = false
    }
    "database" = {
      predefined_egress = []
      self_referencing = false
    }
    "custom" = {
      predefined_egress = []
      self_referencing = false
    }
  }
  
  current_type_config = lookup(local.type_defaults, local.sg_type, local.type_defaults["custom"])
  
  # Process ingress rules
  ingress_rules = [
    for rule in lookup(var.security_group_config, "ingress", []) : {
      from_port                = rule.from_port
      to_port                  = rule.to_port
      protocol                 = rule.protocol
      cidr_blocks              = lookup(rule, "cidr_blocks", null)
      ipv6_cidr_blocks        = lookup(rule, "ipv6_cidr_blocks", null)
      prefix_list_ids         = lookup(rule, "prefix_list_ids", null)
      security_groups         = lookup(rule, "source_security_groups", lookup(rule, "security_groups", null))
      self                    = lookup(rule, "self", null)
      description             = lookup(rule, "description", "Managed by sg-platform")
    }
  ]
  
  # Process egress rules - combine user-defined and type-specific defaults
  user_egress = lookup(var.security_group_config, "egress", [])
  
  # Convert predefined egress to the same format
  predefined_egress = [
    for rule in local.current_type_config.predefined_egress : {
      from_port                = rule.from_port
      to_port                  = rule.to_port
      protocol                 = rule.protocol
      cidr_blocks              = lookup(rule, "cidr_blocks", null)
      ipv6_cidr_blocks        = lookup(rule, "ipv6_cidr_blocks", null)
      prefix_list_ids         = lookup(rule, "prefix_list_ids", null)
      security_groups         = lookup(rule, "source_security_groups", lookup(rule, "security_groups", null))
      self                    = lookup(rule, "self", null)
      description             = lookup(rule, "description", "Predefined rule for ${local.sg_type}")
    }
  ]
  
  # Process user egress rules
  user_egress_processed = [
    for rule in local.user_egress : {
      from_port                = rule.from_port
      to_port                  = rule.to_port
      protocol                 = rule.protocol
      cidr_blocks              = lookup(rule, "cidr_blocks", null)
      ipv6_cidr_blocks        = lookup(rule, "ipv6_cidr_blocks", null)
      prefix_list_ids         = lookup(rule, "prefix_list_ids", null)
      security_groups         = lookup(rule, "source_security_groups", lookup(rule, "security_groups", null))
      self                    = lookup(rule, "self", null)
      description             = lookup(rule, "description", "Managed by sg-platform")
    }
  ]
  
  # Combine predefined and user egress rules
  all_egress_rules = concat(local.predefined_egress, local.user_egress_processed)
  
  # Add self-referencing rule if enabled for this type
  self_ingress_rule = local.current_type_config.self_referencing ? [
    {
      from_port                = 0
      to_port                  = 65535
      protocol                 = "-1"
      cidr_blocks              = null
      ipv6_cidr_blocks        = null
      prefix_list_ids         = null
      security_groups         = null
      self                    = true
      description             = "Self-referencing rule for ${local.sg_type}"
    }
  ] : []
  
  # Final ingress rules with optional self-referencing
  final_ingress_rules = concat(local.ingress_rules, local.self_ingress_rule)
  
  # Resolve prefix list references if they're using names instead of IDs
  resolved_prefix_lists = var.prefix_list_mappings
}

# Main security group resource
resource "aws_security_group" "main" {
  name        = var.security_group_config.name
  description = var.security_group_config.description
  vpc_id      = var.vpc_id

  # Use name_prefix if name conflicts are expected
  lifecycle {
    create_before_destroy = true
  }

  tags = local.final_tags
}

# Ingress rules
resource "aws_security_group_rule" "ingress" {
  count = length(local.final_ingress_rules)

  type              = "ingress"
  from_port         = local.final_ingress_rules[count.index].from_port
  to_port           = local.final_ingress_rules[count.index].to_port
  protocol          = local.final_ingress_rules[count.index].protocol
  security_group_id = aws_security_group.main.id

  # CIDR blocks
  cidr_blocks = local.final_ingress_rules[count.index].cidr_blocks

  # IPv6 CIDR blocks
  ipv6_cidr_blocks = local.final_ingress_rules[count.index].ipv6_cidr_blocks

  # Prefix lists (resolve names to IDs if needed)
  prefix_list_ids = local.final_ingress_rules[count.index].prefix_list_ids != null ? [
    for pl in local.final_ingress_rules[count.index].prefix_list_ids :
    lookup(local.resolved_prefix_lists, pl, pl)
  ] : null

  # Source security groups (resolve names to IDs if needed)
  source_security_group_id = (
    local.final_ingress_rules[count.index].security_groups != null &&
    length(local.final_ingress_rules[count.index].security_groups) > 0
  ) ? lookup(var.security_group_mappings, local.final_ingress_rules[count.index].security_groups[0], local.final_ingress_rules[count.index].security_groups[0]) : null

  # Self-referencing
  self = local.final_ingress_rules[count.index].self

  description = local.final_ingress_rules[count.index].description
}

# Egress rules
resource "aws_security_group_rule" "egress" {
  count = length(local.all_egress_rules)

  type              = "egress"
  from_port         = local.all_egress_rules[count.index].from_port
  to_port           = local.all_egress_rules[count.index].to_port
  protocol          = local.all_egress_rules[count.index].protocol
  security_group_id = aws_security_group.main.id

  # CIDR blocks
  cidr_blocks = local.all_egress_rules[count.index].cidr_blocks

  # IPv6 CIDR blocks
  ipv6_cidr_blocks = local.all_egress_rules[count.index].ipv6_cidr_blocks

  # Prefix lists (resolve names to IDs if needed)
  prefix_list_ids = local.all_egress_rules[count.index].prefix_list_ids != null ? [
    for pl in local.all_egress_rules[count.index].prefix_list_ids :
    lookup(local.resolved_prefix_lists, pl, pl)
  ] : null

  # Destination security groups (resolve names to IDs if needed)
  source_security_group_id = (
    local.all_egress_rules[count.index].security_groups != null &&
    length(local.all_egress_rules[count.index].security_groups) > 0
  ) ? lookup(var.security_group_mappings, local.all_egress_rules[count.index].security_groups[0], local.all_egress_rules[count.index].security_groups[0]) : null

  # Self-referencing
  self = local.all_egress_rules[count.index].self

  description = local.all_egress_rules[count.index].description
}

# Default egress rule (allow all outbound) if no egress rules are specified
resource "aws_security_group_rule" "default_egress" {
  count = length(local.all_egress_rules) == 0 ? 1 : 0

  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.main.id
  description       = "Default allow all outbound"
}

# Optional: Create VPC flow logs for this security group if enabled
resource "aws_flow_log" "security_group_flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  iam_role_arn    = var.flow_logs_role_arn
  log_destination = var.flow_logs_destination_arn
  traffic_type    = "ALL"
  
  # This is a placeholder - AWS doesn't support per-SG flow logs directly
  # You would typically create VPC-level flow logs and filter by SG in analysis
  vpc_id = var.vpc_id

  tags = merge(local.final_tags, {
    Name = "${var.security_group_config.name}-flow-logs"
  })
}

# Security group rule analysis (for insights and compliance)
locals {
  rule_analysis = {
    total_ingress_rules = length(local.final_ingress_rules)
    total_egress_rules  = length(local.all_egress_rules)
    has_wide_open_ingress = anytrue([
      for rule in local.final_ingress_rules :
      contains(lookup(rule, "cidr_blocks", []), "0.0.0.0/0") && 
      rule.from_port == 0 && rule.to_port == 65535
    ])
    has_wide_open_egress = anytrue([
      for rule in local.all_egress_rules :
      contains(lookup(rule, "cidr_blocks", []), "0.0.0.0/0") && 
      rule.from_port == 0 && rule.to_port == 65535
    ])
    security_group_type = local.sg_type
    uses_prefix_lists = anytrue([
      for rule in concat(local.final_ingress_rules, local.all_egress_rules) :
      lookup(rule, "prefix_list_ids", null) != null
    ])
    uses_security_group_references = anytrue([
      for rule in concat(local.final_ingress_rules, local.all_egress_rules) :
      lookup(rule, "security_groups", null) != null
    ])
  }
}