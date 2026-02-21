# AWS Security Group Platform - Account Module
# This module reads security-groups.yaml directly using yamldecode() and creates all resources

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Load and parse the YAML configuration
locals {
  # Load the security groups YAML configuration
  config = yamldecode(file(var.yaml_file))
  
  # Load guardrails configuration
  guardrails = yamldecode(file("${path.module}/../../../guardrails.yaml"))
  
  # Load prefix lists configuration
  prefix_lists = yamldecode(file("${path.module}/../../../prefix-lists.yaml"))
  
  # Extract account ID and validate
  account_id = tostring(local.config.account_id)
  
  # Get current caller identity for validation
  current_account_id = data.aws_caller_identity.current.account_id
  
  # Validate we're in the correct account
  account_validation = local.account_id == local.current_account_id
  
  # Common tags for all resources
  common_tags = merge(
    {
      ManagedBy   = "sg-platform"
      AccountId   = local.account_id
      Environment = lookup(local.config, "environment", "unknown")
      Repository  = "aws-security-groups"
      Terraform   = "true"
    },
    lookup(local.config, "tags", {})
  )
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Validation check - fail if we're in the wrong account
resource "null_resource" "account_validation" {
  count = local.account_validation ? 0 : 1
  
  provisioner "local-exec" {
    command = "echo 'ERROR: Account ID mismatch. Expected ${local.account_id}, got ${local.current_account_id}' && exit 1"
  }
}

# VPC Discovery Module
module "vpc_discovery" {
  source = "../vpc-discovery"
  
  account_id                = local.account_id
  vpc_id                   = lookup(lookup(local.config, "vpc", {}), "vpc_id", "auto")
  vpc_filter_tags          = lookup(lookup(local.config, "vpc", {}), "filter_tags", {})
  require_internet_access  = lookup(lookup(local.config, "vpc", {}), "require_internet_access", false)
  require_private_subnets  = lookup(lookup(local.config, "vpc", {}), "require_private_subnets", false)  
  require_public_subnets   = lookup(lookup(local.config, "vpc", {}), "require_public_subnets", false)
  min_availability_zones   = lookup(lookup(local.config, "vpc", {}), "min_availability_zones", 1)
}

# Baseline Security Groups (if specified)
module "baseline" {
  count  = length(lookup(local.config, "baseline_profiles", [])) > 0 ? 1 : 0
  source = "../../baseline"
  
  account_id        = local.account_id
  vpc_id           = module.vpc_discovery.vpc_id
  region           = data.aws_region.current.name
  baseline_profiles = lookup(local.config, "baseline_profiles", [])
  environment      = lookup(local.config, "environment", "unknown")
  tags             = local.common_tags
}

# Security Groups
module "security_groups" {
  for_each = lookup(local.config, "security_groups", {})
  source   = "../security-group"
  
  security_group_config = merge(each.value, {
    name = each.key
  })
  
  vpc_id     = lookup(each.value, "vpc_id", null) != null ? each.value.vpc_id : module.vpc_discovery.vpc_id
  account_id = local.account_id
  environment = lookup(local.config, "environment", "unknown")
  tags       = local.common_tags
  
  # Pass mappings for resolving references
  security_group_mappings = {
    # Create mapping of SG names to their resource references
    # This will be populated dynamically as SGs are created
    for sg_name, sg_config in lookup(local.config, "security_groups", {}) : 
    sg_name => module.security_groups[sg_name].security_group_id
  }
  
  # Pass baseline security groups if they exist
  baseline_security_groups = length(lookup(local.config, "baseline_profiles", [])) > 0 ? {
    for key, value in module.baseline[0] : key => value
    if can(regex(".*_security_group_id$", key))
  } : {}
  
  # Prefix list mappings from the loaded configuration
  prefix_list_mappings = local.prefix_lists
  
  depends_on = [module.vpc_discovery]
}

# Locals for processing rules and resolving references
locals {
  # Create a map of all security groups (including baseline) for reference resolution
  all_security_groups = merge(
    # User-defined security groups
    {
      for sg_name, sg_module in module.security_groups : 
      sg_name => sg_module.security_group_id
    },
    # Baseline security groups (if any)
    length(lookup(local.config, "baseline_profiles", [])) > 0 ? {
      for key, value in module.baseline[0] : 
      replace(key, "_security_group_id", "") => value
      if can(regex(".*_security_group_id$", key))
    } : {}
  )
  
  # Process security group rules to resolve self-references and create dependency order
  security_group_dependencies = {
    for sg_name, sg_config in lookup(local.config, "security_groups", {}) : sg_name => {
      depends_on_sgs = distinct(flatten([
        # Extract SG references from ingress rules
        for rule in lookup(sg_config, "ingress", []) :
        lookup(rule, "security_groups", [])
      ]))
      references_self = anytrue([
        for rule in concat(
          lookup(sg_config, "ingress", []),
          lookup(sg_config, "egress", [])
        ) : lookup(rule, "self", false)
      ])
    }
  }
}