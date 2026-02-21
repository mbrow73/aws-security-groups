# AWS Security Group Platform - Account Module Outputs

# Account Information
output "account_id" {
  description = "AWS Account ID"
  value       = local.account_id
}

output "region" {
  description = "AWS Region"
  value       = data.aws_region.current.name
}

output "account_validation" {
  description = "Account ID validation result"
  value = {
    expected_account = local.account_id
    actual_account   = local.current_account_id
    is_valid        = local.account_validation
  }
}

# VPC Discovery Results
output "vpc_id" {
  description = "ID of the discovered/selected VPC"
  value       = module.vpc_discovery.vpc_id
}

output "vpc_cidr" {
  description = "CIDR block of the selected VPC"
  value       = module.vpc_discovery.vpc_cidr_block
}

output "vpc_discovery_results" {
  description = "Complete VPC discovery results"
  value = {
    vpc_id              = module.vpc_discovery.vpc_id
    vpc_cidr           = module.vpc_discovery.vpc_cidr_block
    availability_zones = module.vpc_discovery.availability_zones
    has_internet_access = module.vpc_discovery.has_internet_access
    has_private_subnets = module.vpc_discovery.has_private_subnets
    has_public_subnets  = module.vpc_discovery.has_public_subnets
    discovery_method   = module.vpc_discovery.discovery_method
    validation_results = module.vpc_discovery.validation_results
    warnings          = module.vpc_discovery.warnings
  }
}

output "subnets_by_type" {
  description = "Subnets organized by type"
  value       = module.vpc_discovery.subnets_by_type
}

output "subnet_cidrs" {
  description = "Subnet CIDR blocks by type"
  value = {
    private  = module.vpc_discovery.private_subnet_cidrs
    public   = module.vpc_discovery.public_subnet_cidrs
    database = module.vpc_discovery.database_subnet_cidrs
    internal = module.vpc_discovery.internal_subnet_cidrs
  }
}

# Security Groups
output "security_groups" {
  description = "Created security groups with their details"
  value = {
    for sg_name, sg_module in module.security_groups : sg_name => {
      id   = sg_module.security_group_id
      arn  = sg_module.security_group_arn
      name = sg_module.security_group_name
      vpc_id = sg_module.security_group_vpc_id
      tags = sg_module.security_group_tags
    }
  }
}

output "security_group_ids" {
  description = "Map of security group names to their IDs"
  value = {
    for sg_name, sg_module in module.security_groups : sg_name => sg_module.security_group_id
  }
}

output "security_group_arns" {
  description = "Map of security group names to their ARNs"
  value = {
    for sg_name, sg_module in module.security_groups : sg_name => sg_module.security_group_arn
  }
}

# Baseline Security Groups (if enabled)
output "baseline_security_groups" {
  description = "Baseline security groups (if deployed)"
  value = length(lookup(local.config, "baseline_profiles", [])) > 0 ? {
    for key, value in module.baseline[0] : key => value
    if can(regex(".*_security_group_id$", key))
  } : {}
}

output "baseline_profiles" {
  description = "List of enabled baseline profiles"
  value       = lookup(local.config, "baseline_profiles", [])
}

# Configuration Analysis
output "configuration_summary" {
  description = "Summary of the loaded configuration"
  value = {
    account_id         = local.account_id
    environment       = lookup(local.config, "environment", "unknown")
    vpc_configuration = lookup(local.config, "vpc", {})
    baseline_profiles = lookup(local.config, "baseline_profiles", [])
    security_group_count = length(lookup(local.config, "security_groups", {}))
    security_group_names = keys(lookup(local.config, "security_groups", {}))
    has_global_tags   = length(lookup(local.config, "tags", {})) > 0
    global_tags       = lookup(local.config, "tags", {})
  }
}

# Rule Analysis
output "security_group_analysis" {
  description = "Analysis of security group rules and patterns"
  value = {
    total_security_groups = length(lookup(local.config, "security_groups", {}))
    dependencies         = local.security_group_dependencies
    
    rule_statistics = {
      for sg_name, sg_config in lookup(local.config, "security_groups", {}) : sg_name => {
        ingress_rule_count = length(lookup(sg_config, "ingress", []))
        egress_rule_count  = length(lookup(sg_config, "egress", []))
        has_self_reference = anytrue([
          for rule in concat(
            lookup(sg_config, "ingress", []),
            lookup(sg_config, "egress", [])
          ) : lookup(rule, "self", false)
        ])
        references_other_sgs = length(distinct(flatten([
          for rule in concat(
            lookup(sg_config, "ingress", []),
            lookup(sg_config, "egress", [])
          ) : lookup(rule, "security_groups", [])
        ]))) > 0
        uses_prefix_lists = anytrue([
          for rule in concat(
            lookup(sg_config, "ingress", []),
            lookup(sg_config, "egress", [])
          ) : length(lookup(rule, "prefix_list_ids", [])) > 0
        ])
        allows_internet_ingress = anytrue([
          for rule in lookup(sg_config, "ingress", []) : 
          contains(lookup(rule, "cidr_blocks", []), "0.0.0.0/0")
        ])
      }
    }
  }
}

# Common tags applied
output "common_tags" {
  description = "Common tags applied to all resources"
  value       = local.common_tags
}

# Resource metadata
output "deployment_info" {
  description = "Information about this deployment"
  value = {
    terraform_version    = "~> 1.6"
    module_version      = "2.0.0"  # Updated for yamldecode approach
    deployment_time     = timestamp()
    config_file_path    = local.config_file_path
    managed_by          = "sg-platform"
    deployment_method   = "yamldecode"
  }
}

# Validation results
output "validation_warnings" {
  description = "Configuration validation warnings"
  value = compact([
    !local.account_validation ? "Account ID mismatch detected" : "",
    length(lookup(local.config, "security_groups", {})) == 0 ? "No security groups defined" : "",
    length(module.vpc_discovery.warnings) > 0 ? "VPC discovery warnings present" : "",
  ])
}

# Networking insights
output "networking_analysis" {
  description = "Network configuration analysis"
  value = {
    vpc = {
      id                  = module.vpc_discovery.vpc_id
      cidr               = module.vpc_discovery.vpc_cidr_block
      has_internet_gateway = module.vpc_discovery.internet_gateway_id != null
      nat_gateway_count   = length(module.vpc_discovery.nat_gateway_ids)
      vpc_endpoint_count  = length(module.vpc_discovery.vpc_endpoint_ids)
    }
    
    subnets = {
      total_count        = length(module.vpc_discovery.subnet_ids)
      private_count      = length(module.vpc_discovery.private_subnet_ids)
      public_count       = length(module.vpc_discovery.public_subnet_ids)
      database_count     = length(module.vpc_discovery.database_subnet_ids)
      availability_zones = module.vpc_discovery.availability_zones
      is_multi_az       = module.vpc_discovery.is_multi_az
    }
    
    security = {
      total_sgs_in_vpc     = module.vpc_discovery.security_group_count
      new_sgs_created      = length(lookup(local.config, "security_groups", {}))
      baseline_sgs_created = length(lookup(local.config, "baseline_profiles", []))
    }
  }
}

# Reference mappings (for troubleshooting)
output "reference_mappings" {
  description = "Reference mappings used for rule resolution"
  value = {
    security_groups = local.all_security_groups
    prefix_lists   = local.prefix_lists
  }
  sensitive = false  # These are resource IDs, not sensitive data
}

# Cost estimation data (if enabled)
output "cost_estimation" {
  description = "Cost estimation data for the deployed resources"
  value = var.enable_cost_monitoring ? {
    security_groups_count = length(lookup(local.config, "security_groups", {}))
    baseline_profiles    = length(lookup(local.config, "baseline_profiles", []))
    estimated_monthly_cost = {
      security_groups = length(lookup(local.config, "security_groups", {})) * 0.00  # SGs are free
      flow_logs      = var.create_flow_logs ? 10.00 : 0.00  # Estimated based on usage
      insights       = var.enable_security_insights ? 5.00 : 0.00
    }
  } : null
}

# Terraform state metadata
output "terraform_state_info" {
  description = "Terraform state and workspace information"
  value = {
    workspace_name = terraform.workspace
    state_version  = "4"  # Terraform state version
    provider_versions = {
      aws = "~> 5.0"
    }
  }
}