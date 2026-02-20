# AWS Security Group Platform - VPC Discovery Module Outputs

# Primary VPC Information
output "vpc_id" {
  description = "ID of the selected/discovered VPC"
  value       = local.vpc_selection_valid ? local.selected_vpc.id : null
}

output "vpc_cidr_block" {
  description = "CIDR block of the selected VPC"
  value       = local.vpc_selection_valid ? local.selected_vpc.cidr_block : null
}

output "vpc_cidr" {
  description = "Alias for vpc_cidr_block for backward compatibility"
  value       = local.vpc_selection_valid ? local.selected_vpc.cidr_block : null
}

output "vpc_state" {
  description = "State of the selected VPC"
  value       = local.vpc_selection_valid ? local.selected_vpc.state : null
}

output "vpc_is_default" {
  description = "Whether the selected VPC is the default VPC"
  value       = local.vpc_selection_valid ? local.selected_vpc.is_default : null
}

output "vpc_tags" {
  description = "Tags associated with the selected VPC"
  value       = local.vpc_selection_valid ? local.selected_vpc.tags : {}
}

output "vpc_dns_support" {
  description = "Whether DNS resolution is supported in the VPC"
  value       = local.vpc_selection_valid ? local.selected_vpc.enable_dns_support : null
}

output "vpc_dns_hostnames" {
  description = "Whether DNS hostnames are enabled in the VPC"
  value       = local.vpc_selection_valid ? local.selected_vpc.enable_dns_hostnames : null
}

# Subnet Information
output "subnet_ids" {
  description = "List of all subnet IDs in the selected VPC"
  value = local.vpc_selection_valid ? [
    for subnet in local.enhanced_subnet_details : subnet.id
  ] : []
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value = local.vpc_selection_valid ? [
    for subnet in local.enhanced_subnet_details : subnet.id
    if subnet.enhanced_type == "private"
  ] : []
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value = local.vpc_selection_valid ? [
    for subnet in local.enhanced_subnet_details : subnet.id
    if subnet.enhanced_type == "public"
  ] : []
}

output "database_subnet_ids" {
  description = "List of database subnet IDs"
  value = local.vpc_selection_valid ? [
    for subnet in local.enhanced_subnet_details : subnet.id
    if subnet.enhanced_type == "database"
  ] : []
}

output "internal_subnet_ids" {
  description = "List of internal subnet IDs"
  value = local.vpc_selection_valid ? [
    for subnet in local.enhanced_subnet_details : subnet.id
    if subnet.enhanced_type == "internal"
  ] : []
}

# Subnet CIDR Information
output "subnet_cidrs" {
  description = "List of all subnet CIDR blocks"
  value = local.vpc_selection_valid ? [
    for subnet in local.enhanced_subnet_details : subnet.cidr_block
  ] : []
}

output "private_subnet_cidrs" {
  description = "List of private subnet CIDR blocks"
  value = local.vpc_selection_valid ? lookup(local.final_subnet_cidrs_by_type, "private", []) : []
}

output "public_subnet_cidrs" {
  description = "List of public subnet CIDR blocks"
  value = local.vpc_selection_valid ? lookup(local.final_subnet_cidrs_by_type, "public", []) : []
}

output "database_subnet_cidrs" {
  description = "List of database subnet CIDR blocks"
  value = local.vpc_selection_valid ? lookup(local.final_subnet_cidrs_by_type, "database", []) : []
}

output "internal_subnet_cidrs" {
  description = "List of internal subnet CIDR blocks"
  value = local.vpc_selection_valid ? lookup(local.final_subnet_cidrs_by_type, "internal", []) : []
}

# Subnet Details by Type
output "subnets_by_type" {
  description = "Map of subnet details organized by type"
  value = local.vpc_selection_valid ? {
    for type, subnets in local.final_subnets_by_type : type => [
      for subnet in subnets : {
        id                = subnet.id
        cidr_block       = subnet.cidr_block
        availability_zone = subnet.availability_zone
        tags             = subnet.tags
        state            = subnet.state
      }
    ]
  } : {}
}

output "subnets_by_az" {
  description = "Map of subnets organized by availability zone"
  value = local.vpc_selection_valid ? {
    for az in local.availability_zones : az => [
      for subnet in local.enhanced_subnet_details : {
        id         = subnet.id
        cidr_block = subnet.cidr_block
        type       = subnet.enhanced_type
        tags       = subnet.tags
      }
      if subnet.availability_zone == az
    ]
  } : {}
}

# Availability Zone Information
output "availability_zones" {
  description = "List of availability zones in the selected VPC"
  value       = local.vpc_selection_valid ? local.availability_zones : []
}

output "az_distribution" {
  description = "Distribution of subnets across availability zones"
  value       = local.vpc_selection_valid ? local.az_distribution : {}
}

# Network Infrastructure
output "internet_gateway_id" {
  description = "Internet Gateway ID attached to the VPC"
  value       = local.vpc_selection_valid ? try(data.aws_internet_gateway.vpc[0].internet_gateway_id, null) : null
}

output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs in the VPC"
  value       = local.vpc_selection_valid ? try(data.aws_nat_gateways.vpc[0].ids, []) : []
}

output "vpc_endpoint_ids" {
  description = "List of VPC Endpoint IDs"
  value       = local.vpc_selection_valid ? try(data.aws_vpc_endpoints.vpc[0].ids, []) : []
}

output "network_acl_ids" {
  description = "List of Network ACL IDs in the VPC"
  value       = local.vpc_selection_valid ? try(data.aws_network_acls.vpc[0].ids, []) : []
}

# Route Table Information
output "route_table_ids" {
  description = "List of Route Table IDs in the VPC"
  value       = local.vpc_selection_valid ? keys(local.route_analysis) : []
}

output "route_analysis" {
  description = "Detailed route table analysis for subnet categorization"
  value = local.vpc_selection_valid && var.include_sensitive_data ? {
    for rt_id, rt in local.route_analysis : rt_id => {
      id                  = rt.id
      subnet_ids         = rt.subnet_ids
      has_internet_gateway = rt.has_internet_gateway
      has_nat_gateway    = rt.has_nat_gateway
      tags               = rt.tags
    }
  } : {}
  sensitive = var.include_sensitive_data
}

# Security Groups
output "existing_security_group_ids" {
  description = "List of existing Security Group IDs in the VPC"
  value       = local.vpc_selection_valid ? try(data.aws_security_groups.vpc[0].ids, []) : []
}

output "security_group_count" {
  description = "Number of existing security groups in the VPC"
  value       = local.vpc_selection_valid ? try(length(data.aws_security_groups.vpc[0].ids), 0) : 0
}

# Discovery Metadata
output "discovery_method" {
  description = "Method used for VPC discovery (explicit/auto)"
  value       = var.vpc_id != "auto" ? "explicit" : "auto"
}

output "vpc_count_discovered" {
  description = "Total number of VPCs discovered in the account"
  value       = length(data.aws_vpcs.all.ids)
}

output "available_vpcs" {
  description = "List of all available VPCs with basic info"
  value = [
    for vpc in local.available_vpcs : {
      id         = vpc.id
      cidr_block = vpc.cidr_block
      is_default = vpc.is_default
      tags       = vpc.tags
    }
  ]
}

# Validation Results
output "validation_results" {
  description = "VPC discovery and validation results"
  value       = local.validation_results
}

output "has_internet_access" {
  description = "Whether the VPC has internet access (IGW or NAT)"
  value       = local.validation_results.has_internet_access
}

output "has_private_subnets" {
  description = "Whether the VPC has private subnets"
  value       = local.validation_results.has_private_subnets
}

output "has_public_subnets" {
  description = "Whether the VPC has public subnets"
  value       = local.validation_results.has_public_subnets
}

output "is_multi_az" {
  description = "Whether the VPC spans multiple availability zones"
  value       = local.validation_results.multi_az
}

# Comprehensive Analysis (Optional)
output "vpc_analysis" {
  description = "Comprehensive VPC analysis including networking and security"
  value       = var.detailed_analysis && local.vpc_selection_valid ? local.vpc_analysis : null
}

# Context Information
output "account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS Region"
  value       = data.aws_region.current.name
}

# Error/Warning Messages
output "warnings" {
  description = "List of warnings encountered during discovery"
  value = compact([
    local.validation_results.multiple_vpcs && var.vpc_id == "auto" ? "Multiple VPCs found - auto-selected based on priority rules" : "",
    !local.validation_results.has_internet_access && var.require_internet_access ? "Selected VPC does not have internet access" : "",
    !local.validation_results.has_private_subnets && var.require_private_subnets ? "Selected VPC does not have private subnets" : "",
    !local.validation_results.has_public_subnets && var.require_public_subnets ? "Selected VPC does not have public subnets" : "",
    !local.validation_results.multi_az && var.min_availability_zones > 1 ? "Selected VPC does not span required number of AZs" : "",
  ])
}

# Export Functionality (for debugging)
output "discovery_timestamp" {
  description = "Timestamp of the discovery operation"
  value       = timestamp()
}

output "terraform_version" {
  description = "Terraform version used for discovery"
  value       = "~> 1.6"
}

# Backward Compatibility Aliases
output "vpc" {
  description = "VPC information (legacy format for backward compatibility)"
  value = local.vpc_selection_valid ? {
    id                     = local.selected_vpc.id
    cidr_block            = local.selected_vpc.cidr_block
    state                 = local.selected_vpc.state
    tags                  = local.selected_vpc.tags
    enable_dns_support    = local.selected_vpc.enable_dns_support
    enable_dns_hostnames  = local.selected_vpc.enable_dns_hostnames
  } : null
}

output "subnets" {
  description = "Subnet information (legacy format for backward compatibility)"
  value = local.vpc_selection_valid ? {
    all     = local.enhanced_subnet_details
    private = lookup(local.final_subnets_by_type, "private", [])
    public  = lookup(local.final_subnets_by_type, "public", [])
    database = lookup(local.final_subnets_by_type, "database", [])
  } : {}
}