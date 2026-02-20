# AWS Security Group Platform - Security Group Module Outputs

# Main security group information
output "security_group_id" {
  description = "ID of the created security group"
  value       = aws_security_group.main.id
}

output "security_group_arn" {
  description = "ARN of the created security group"
  value       = aws_security_group.main.arn
}

output "security_group_name" {
  description = "Name of the created security group"
  value       = aws_security_group.main.name
}

output "security_group_description" {
  description = "Description of the created security group"
  value       = aws_security_group.main.description
}

output "security_group_vpc_id" {
  description = "VPC ID of the created security group"
  value       = aws_security_group.main.vpc_id
}

output "security_group_owner_id" {
  description = "Owner ID of the created security group"
  value       = aws_security_group.main.owner_id
}

output "security_group_tags" {
  description = "Tags applied to the security group"
  value       = aws_security_group.main.tags_all
}

# Rule information
output "ingress_rules" {
  description = "List of ingress rules created"
  value = [
    for rule in aws_security_group_rule.ingress : {
      id                       = rule.id
      type                     = rule.type
      from_port               = rule.from_port
      to_port                 = rule.to_port
      protocol                = rule.protocol
      cidr_blocks             = rule.cidr_blocks
      ipv6_cidr_blocks       = rule.ipv6_cidr_blocks
      prefix_list_ids        = rule.prefix_list_ids
      source_security_group_id = rule.source_security_group_id
      self                   = rule.self
      description            = rule.description
    }
  ]
}

output "egress_rules" {
  description = "List of egress rules created"
  value = [
    for rule in aws_security_group_rule.egress : {
      id                       = rule.id
      type                     = rule.type
      from_port               = rule.from_port
      to_port                 = rule.to_port
      protocol                = rule.protocol
      cidr_blocks             = rule.cidr_blocks
      ipv6_cidr_blocks       = rule.ipv6_cidr_blocks
      prefix_list_ids        = rule.prefix_list_ids
      source_security_group_id = rule.source_security_group_id
      self                   = rule.self
      description            = rule.description
    }
  ]
}

output "total_rules_count" {
  description = "Total number of rules (ingress + egress) in the security group"
  value = {
    ingress = length(aws_security_group_rule.ingress)
    egress  = length(aws_security_group_rule.egress) + length(aws_security_group_rule.default_egress)
    total   = length(aws_security_group_rule.ingress) + length(aws_security_group_rule.egress) + length(aws_security_group_rule.default_egress)
  }
}

# Security group type and configuration
output "security_group_type" {
  description = "Type of security group (eks-nodes, nlb, web, etc.)"
  value       = local.sg_type
}

output "security_group_config" {
  description = "Original security group configuration from YAML"
  value       = var.security_group_config
}

# Rule analysis and insights
output "rule_analysis" {
  description = "Analysis of security group rules for insights and compliance"
  value       = local.rule_analysis
}

output "security_insights" {
  description = "Security insights and recommendations"
  value = {
    has_wide_open_ingress = local.rule_analysis.has_wide_open_ingress
    has_wide_open_egress  = local.rule_analysis.has_wide_open_egress
    uses_best_practices = {
      uses_prefix_lists                = local.rule_analysis.uses_prefix_lists
      uses_security_group_references  = local.rule_analysis.uses_security_group_references
      has_descriptions                = alltrue([
        for rule in concat(local.final_ingress_rules, local.all_egress_rules) :
        lookup(rule, "description", "") != ""
      ])
    }
    rule_density = {
      ingress_rules_count = local.rule_analysis.total_ingress_rules
      egress_rules_count  = local.rule_analysis.total_egress_rules
      approaching_limits  = (local.rule_analysis.total_ingress_rules > 50 || local.rule_analysis.total_egress_rules > 50)
    }
  }
}

# Compliance information
output "compliance_status" {
  description = "Compliance status based on configured mode"
  value = {
    mode = var.compliance_mode
    violations = []  # Would be populated by validation logic
    recommendations = []  # Would be populated by analysis logic
  }
}

# Resource relationships
output "referenced_resources" {
  description = "Resources referenced by this security group"
  value = {
    baseline_security_groups = [
      for rule in concat(local.final_ingress_rules, local.all_egress_rules) :
      lookup(rule, "security_groups", [])
      if lookup(rule, "security_groups", null) != null
    ]
    prefix_lists = [
      for rule in concat(local.final_ingress_rules, local.all_egress_rules) :
      lookup(rule, "prefix_list_ids", [])
      if lookup(rule, "prefix_list_ids", null) != null
    ]
  }
}

# Flow logs information
output "flow_logs" {
  description = "VPC Flow Logs information (if enabled)"
  value = var.enable_flow_logs ? {
    id           = try(aws_flow_log.security_group_flow_logs[0].id, null)
    arn          = try(aws_flow_log.security_group_flow_logs[0].arn, null)
    status       = try(aws_flow_log.security_group_flow_logs[0].flow_log_status, null)
    destination  = var.flow_logs_destination_arn
  } : null
}

# Metadata and deployment information
output "deployment_metadata" {
  description = "Deployment metadata for tracking and management"
  value = {
    module_version     = "1.0.0"
    terraform_version  = terraform.version
    deployment_time    = timestamp()
    account_id         = var.account_id
    vpc_id            = var.vpc_id
    environment       = var.environment
    managed_by        = "sg-platform"
  }
}

# For use in other modules and configurations
output "security_group_reference" {
  description = "Reference information for use in other configurations"
  value = {
    id          = aws_security_group.main.id
    name        = aws_security_group.main.name
    type        = local.sg_type
    vpc_id      = aws_security_group.main.vpc_id
    account_id  = var.account_id
    environment = var.environment
  }
}

# Cost optimization insights
output "cost_optimization" {
  description = "Cost optimization insights and recommendations"
  value = {
    rule_complexity = local.rule_analysis.total_ingress_rules + local.rule_analysis.total_egress_rules
    consolidation_opportunities = {
      # Logic to identify rules that could be consolidated
      duplicate_cidrs = false  # Would be calculated
      overlapping_ranges = false  # Would be calculated
    }
    estimated_monthly_cost = {
      # Rough estimates based on rule count and traffic patterns
      base_cost = 0.0  # Security groups themselves are free
      data_processing = 0.0  # Based on flow logs if enabled
    }
  }
}

# Security posture assessment
output "security_posture" {
  description = "Security posture assessment of the security group"
  value = {
    risk_level = (
      local.rule_analysis.has_wide_open_ingress ? "HIGH" :
      local.rule_analysis.has_wide_open_egress ? "MEDIUM" :
      "LOW"
    )
    
    security_score = (
      100 -
      (local.rule_analysis.has_wide_open_ingress ? 40 : 0) -
      (local.rule_analysis.has_wide_open_egress ? 20 : 0) -
      (local.rule_analysis.uses_prefix_lists ? 0 : 10) -
      (local.rule_analysis.uses_security_group_references ? 0 : 10)
    )
    
    recommendations = concat(
      local.rule_analysis.has_wide_open_ingress ? ["Restrict overly permissive ingress rules"] : [],
      local.rule_analysis.has_wide_open_egress ? ["Consider restricting egress rules"] : [],
      !local.rule_analysis.uses_prefix_lists ? ["Consider using prefix lists for better management"] : [],
      !local.rule_analysis.uses_security_group_references ? ["Consider using security group references instead of CIDR blocks where appropriate"] : []
    )
  }
}

# Debug information (only in development)
output "debug_information" {
  description = "Debug information for troubleshooting (only in non-production)"
  value = var.environment != "production" ? {
    local_variables = {
      sg_type              = local.sg_type
      current_type_config  = local.current_type_config
      final_ingress_rules  = local.final_ingress_rules
      all_egress_rules     = local.all_egress_rules
    }
    input_mappings = {
      security_group_mappings = var.security_group_mappings
      prefix_list_mappings   = var.prefix_list_mappings
    }
  } : null
  
  sensitive = true  # Mark as sensitive to avoid accidental exposure
}