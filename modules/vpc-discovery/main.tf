# AWS Security Group Platform - VPC Discovery Module
# Automatically discovers VPC information for security group deployment

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Get current caller identity for context
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# Discover VPCs in the account
data "aws_vpcs" "all" {
  tags = var.vpc_filter_tags
}

# Get details for each VPC
data "aws_vpc" "discovered" {
  for_each = toset(data.aws_vpcs.all.ids)
  id       = each.value
}

# Auto-select VPC if not explicitly provided
locals {
  # If a specific VPC ID is provided, use it
  selected_vpc_id = var.vpc_id != "auto" ? var.vpc_id : null
  
  # Auto-discovery logic for single VPC accounts
  discovered_vpcs = [
    for vpc_id, vpc in data.aws_vpc.discovered : {
      id                     = vpc.id
      cidr_block            = vpc.cidr_block
      state                 = vpc.state
      is_default            = vpc.default_route_table_id != null
      tags                  = vpc.tags
      enable_dns_support    = vpc.enable_dns_support
      enable_dns_hostnames  = vpc.enable_dns_hostnames
      instance_tenancy      = vpc.instance_tenancy
      main_route_table_id   = vpc.main_route_table_id
      default_route_table_id = vpc.default_route_table_id
    }
  ]
  
  # Filter available VPCs
  available_vpcs = [
    for vpc in local.discovered_vpcs : vpc
    if vpc.state == "available"
  ]
  
  # VPC selection priority:
  # 1. Explicit VPC ID
  # 2. Single available VPC (auto-discovery)
  # 3. VPC tagged with priority tags
  # 4. Default VPC (least preferred)
  
  priority_tagged_vpcs = [
    for vpc in local.available_vpcs : vpc
    if anytrue([
      for tag_key in var.priority_tags :
      lookup(vpc.tags, tag_key, "") != ""
    ])
  ]
  
  non_default_vpcs = [
    for vpc in local.available_vpcs : vpc
    if !vpc.is_default
  ]
  
  default_vpcs = [
    for vpc in local.available_vpcs : vpc
    if vpc.is_default
  ]
  
  # Final VPC selection logic
  auto_selected_vpc = (
    length(local.available_vpcs) == 1 ? local.available_vpcs[0] :
    length(local.priority_tagged_vpcs) > 0 ? local.priority_tagged_vpcs[0] :
    length(local.non_default_vpcs) > 0 ? local.non_default_vpcs[0] :
    length(local.default_vpcs) > 0 ? local.default_vpcs[0] :
    null
  )
  
  # Final selected VPC
  selected_vpc = var.vpc_id != "auto" ? [
    for vpc in local.discovered_vpcs : vpc
    if vpc.id == var.vpc_id
  ][0] : local.auto_selected_vpc
  
  # Validation
  vpc_selection_valid = local.selected_vpc != null
}

# Get subnet information for the selected VPC
data "aws_subnets" "all" {
  count = local.vpc_selection_valid ? 1 : 0
  
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc.id]
  }
  
  tags = var.subnet_filter_tags
}

data "aws_subnet" "details" {
  for_each = local.vpc_selection_valid ? toset(data.aws_subnets.all[0].ids) : toset([])
  id       = each.value
}

# Categorize subnets based on tags and routing
locals {
  subnet_details = local.vpc_selection_valid ? [
    for subnet_id, subnet in data.aws_subnet.details : {
      id                = subnet.id
      cidr_block       = subnet.cidr_block
      availability_zone = subnet.availability_zone
      tags             = subnet.tags
      vpc_id           = subnet.vpc_id
      state            = subnet.state
      
      # Determine subnet type based on tags and routing
      type = (
        can(regex(".*private.*", lower(lookup(subnet.tags, "Name", "")))) ? "private" :
        can(regex(".*public.*", lower(lookup(subnet.tags, "Name", "")))) ? "public" :
        can(regex(".*database.*|.*db.*|.*rds.*", lower(lookup(subnet.tags, "Name", "")))) ? "database" :
        can(regex(".*internal.*", lower(lookup(subnet.tags, "Name", "")))) ? "internal" :
        lookup(subnet.tags, "Type", lookup(subnet.tags, "type", "unknown"))
      )
      
      # Extract environment from tags
      environment = lookup(subnet.tags, "Environment", lookup(subnet.tags, "environment", "unknown"))
    }
  ] : []
  
  # Group subnets by type
  subnets_by_type = {
    for subnet in local.subnet_details : subnet.type => subnet...
  }
  
  # Extract CIDR blocks by type
  subnet_cidrs_by_type = {
    for type, subnets in local.subnets_by_type : type => [
      for subnet in subnets : subnet.cidr_block
    ]
  }
}

# Get route tables to better understand subnet types
data "aws_route_tables" "vpc" {
  count = local.vpc_selection_valid ? 1 : 0
  
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc.id]
  }
}

data "aws_route_table" "details" {
  for_each = local.vpc_selection_valid ? toset(data.aws_route_tables.vpc[0].ids) : toset([])
  route_table_id = each.value
}

# Analyze routing to better categorize subnets
locals {
  route_analysis = local.vpc_selection_valid ? {
    for rt_id, rt in data.aws_route_table.details : rt_id => {
      id = rt.route_table_id
      routes = rt.routes
      subnet_ids = rt.subnet_ids
      vpc_id = rt.vpc_id
      tags = rt.tags
      
      # Check if this route table has internet gateway routes
      has_internet_gateway = anytrue([
        for route in rt.routes : 
        route.gateway_id != null && can(regex("^igw-", route.gateway_id))
      ])
      
      # Check if this route table has NAT gateway routes
      has_nat_gateway = anytrue([
        for route in rt.routes :
        route.nat_gateway_id != null
      ])
    }
  } : {}
  
  # Improve subnet type detection using route analysis
  enhanced_subnet_details = [
    for subnet in local.subnet_details : merge(subnet, {
      # Find associated route table
      route_table_info = try([
        for rt_id, rt in local.route_analysis : rt
        if contains(rt.subnet_ids, subnet.id)
      ][0], null)
      
      # Enhanced type detection
      enhanced_type = (
        # Check route table first for more accurate classification
        try(
          [
            for rt_id, rt in local.route_analysis : 
            rt.has_internet_gateway ? "public" : rt.has_nat_gateway ? "private" : "internal"
            if contains(rt.subnet_ids, subnet.id)
          ][0],
          subnet.type  # Fall back to tag-based detection
        )
      )
    })
  ]
  
  # Final subnet categorization
  final_subnets_by_type = {
    for subnet in local.enhanced_subnet_details : subnet.enhanced_type => subnet...
  }
  
  final_subnet_cidrs_by_type = {
    for type, subnets in local.final_subnets_by_type : type => [
      for subnet in subnets : subnet.cidr_block
    ]
  }
}

# Availability Zone analysis
locals {
  availability_zones = local.vpc_selection_valid ? distinct([
    for subnet in local.enhanced_subnet_details : subnet.availability_zone
  ]) : []
  
  az_distribution = {
    for az in local.availability_zones : az => {
      total_subnets = length([
        for subnet in local.enhanced_subnet_details : subnet
        if subnet.availability_zone == az
      ])
      subnet_types = distinct([
        for subnet in local.enhanced_subnet_details : subnet.enhanced_type
        if subnet.availability_zone == az
      ])
    }
  }
}

# Network ACLs discovery
data "aws_network_acls" "vpc" {
  count = local.vpc_selection_valid ? 1 : 0
  
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc.id]
  }
}

# Security Groups in the VPC (for reference)
data "aws_security_groups" "vpc" {
  count = local.vpc_selection_valid ? 1 : 0
  
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc.id]
  }
  
  tags = var.existing_sg_filter_tags
}

# VPC Endpoints discovery
data "aws_vpc_endpoints" "vpc" {
  count = local.vpc_selection_valid ? 1 : 0
  
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc.id]
  }
}

# Internet Gateways
data "aws_internet_gateway" "vpc" {
  count = local.vpc_selection_valid ? 1 : 0
  
  filter {
    name   = "attachment.vpc-id"
    values = [local.selected_vpc.id]
  }
}

# NAT Gateways
data "aws_nat_gateways" "vpc" {
  count = local.vpc_selection_valid ? 1 : 0
  
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc.id]
  }
}

# Comprehensive VPC analysis
locals {
  vpc_analysis = local.vpc_selection_valid ? {
    vpc = local.selected_vpc
    subnets = {
      total_count = length(local.enhanced_subnet_details)
      by_type     = local.final_subnets_by_type
      by_az       = local.az_distribution
      cidrs       = local.final_subnet_cidrs_by_type
    }
    networking = {
      availability_zones    = local.availability_zones
      internet_gateway_id  = try(data.aws_internet_gateway.vpc[0].internet_gateway_id, null)
      nat_gateway_ids      = try(data.aws_nat_gateways.vpc[0].ids, [])
      vpc_endpoint_ids     = try(data.aws_vpc_endpoints.vpc[0].ids, [])
      network_acl_ids      = try(data.aws_network_acls.vpc[0].ids, [])
    }
    security = {
      existing_security_groups = try(data.aws_security_groups.vpc[0].ids, [])
      total_security_groups    = try(length(data.aws_security_groups.vpc[0].ids), 0)
    }
  } : null
  
  # Validation results
  validation_results = {
    vpc_found = local.vpc_selection_valid
    multiple_vpcs = length(local.available_vpcs) > 1 && var.vpc_id == "auto"
    has_internet_access = local.vpc_selection_valid ? (
      try(data.aws_internet_gateway.vpc[0].internet_gateway_id, null) != null ||
      try(length(data.aws_nat_gateways.vpc[0].ids), 0) > 0
    ) : false
    has_private_subnets = local.vpc_selection_valid ? length(lookup(local.final_subnets_by_type, "private", [])) > 0 : false
    has_public_subnets = local.vpc_selection_valid ? length(lookup(local.final_subnets_by_type, "public", [])) > 0 : false
    multi_az = local.vpc_selection_valid ? length(local.availability_zones) > 1 : false
  }
}