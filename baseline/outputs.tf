# AWS Security Group Platform - Baseline Module Outputs
# These outputs are used by account-specific configurations to reference baseline resources

# VPC Information
output "vpc_id" {
  description = "ID of the VPC where baseline security groups are deployed"
  value       = local.vpc_id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = local.vpc_cidr
}

output "subnet_ids" {
  description = "List of all subnet IDs in the VPC"
  value       = data.aws_subnets.all.ids
}

output "private_subnet_cidrs" {
  description = "CIDR blocks of private subnets"
  value       = local.private_subnet_cidrs
}

output "public_subnet_cidrs" {
  description = "CIDR blocks of public subnets"
  value       = local.public_subnet_cidrs
}

output "database_subnet_cidrs" {
  description = "CIDR blocks of database subnets"
  value       = local.database_subnet_cidrs
}

# Baseline Security Group IDs
output "vpc_endpoints_security_group_id" {
  description = "ID of the VPC endpoints baseline security group"
  value       = aws_security_group.vpc_endpoints.id
}

output "vpc_endpoints_security_group_name" {
  description = "Name of the VPC endpoints baseline security group"
  value       = aws_security_group.vpc_endpoints.name
}

output "waf_to_nlb_security_group_id" {
  description = "ID of the WAF to NLB baseline security group"
  value       = aws_security_group.waf_to_nlb.id
}

output "waf_to_nlb_security_group_name" {
  description = "Name of the WAF to NLB baseline security group"
  value       = aws_security_group.waf_to_nlb.name
}

output "eks_cluster_baseline_security_group_id" {
  description = "ID of the EKS cluster baseline security group"
  value       = aws_security_group.eks_cluster_baseline.id
}

output "eks_cluster_baseline_security_group_name" {
  description = "Name of the EKS cluster baseline security group"
  value       = aws_security_group.eks_cluster_baseline.name
}

output "database_baseline_security_group_id" {
  description = "ID of the database baseline security group"
  value       = aws_security_group.database_baseline.id
}

output "database_baseline_security_group_name" {
  description = "Name of the database baseline security group"
  value       = aws_security_group.database_baseline.name
}

output "lb_to_applications_security_group_id" {
  description = "ID of the load balancer to applications baseline security group"
  value       = aws_security_group.lb_to_applications.id
}

output "lb_to_applications_security_group_name" {
  description = "Name of the load balancer to applications baseline security group"
  value       = aws_security_group.lb_to_applications.name
}

output "monitoring_baseline_security_group_id" {
  description = "ID of the monitoring baseline security group"
  value       = aws_security_group.monitoring_baseline.id
}

output "monitoring_baseline_security_group_name" {
  description = "Name of the monitoring baseline security group"
  value       = aws_security_group.monitoring_baseline.name
}

# Prefix List IDs and ARNs
output "corporate_networks_prefix_list_id" {
  description = "ID of the corporate networks managed prefix list"
  value       = aws_ec2_managed_prefix_list.corporate_networks.id
}

output "corporate_networks_prefix_list_arn" {
  description = "ARN of the corporate networks managed prefix list"
  value       = aws_ec2_managed_prefix_list.corporate_networks.arn
}

output "waf_saas_providers_prefix_list_id" {
  description = "ID of the WAF SaaS providers managed prefix list"
  value       = aws_ec2_managed_prefix_list.waf_saas_providers.id
}

output "waf_saas_providers_prefix_list_arn" {
  description = "ARN of the WAF SaaS providers managed prefix list"
  value       = aws_ec2_managed_prefix_list.waf_saas_providers.arn
}

output "aws_vpc_endpoints_prefix_list_id" {
  description = "ID of the AWS VPC endpoints managed prefix list"
  value       = aws_ec2_managed_prefix_list.aws_vpc_endpoints.id
}

output "aws_vpc_endpoints_prefix_list_arn" {
  description = "ARN of the AWS VPC endpoints managed prefix list"
  value       = aws_ec2_managed_prefix_list.aws_vpc_endpoints.arn
}

output "database_subnets_prefix_list_id" {
  description = "ID of the database subnets managed prefix list"
  value       = aws_ec2_managed_prefix_list.database_subnets.id
}

output "database_subnets_prefix_list_arn" {
  description = "ARN of the database subnets managed prefix list"
  value       = aws_ec2_managed_prefix_list.database_subnets.arn
}

output "alb_subnets_prefix_list_id" {
  description = "ID of the ALB subnets managed prefix list"
  value       = aws_ec2_managed_prefix_list.alb_subnets.id
}

output "alb_subnets_prefix_list_arn" {
  description = "ARN of the ALB subnets managed prefix list"
  value       = aws_ec2_managed_prefix_list.alb_subnets.arn
}

output "ci_cd_systems_prefix_list_id" {
  description = "ID of the CI/CD systems managed prefix list"
  value       = aws_ec2_managed_prefix_list.ci_cd_systems.id
}

output "ci_cd_systems_prefix_list_arn" {
  description = "ARN of the CI/CD systems managed prefix list"
  value       = aws_ec2_managed_prefix_list.ci_cd_systems.arn
}

output "monitoring_services_prefix_list_id" {
  description = "ID of the monitoring services managed prefix list"
  value       = aws_ec2_managed_prefix_list.monitoring_services.id
}

output "monitoring_services_prefix_list_arn" {
  description = "ARN of the monitoring services managed prefix list"
  value       = aws_ec2_managed_prefix_list.monitoring_services.arn
}

# Consolidated outputs for easier reference
output "all_baseline_security_group_ids" {
  description = "Map of all baseline security group IDs"
  value = {
    vpc_endpoints          = aws_security_group.vpc_endpoints.id
    waf_to_nlb            = aws_security_group.waf_to_nlb.id
    eks_cluster_baseline  = aws_security_group.eks_cluster_baseline.id
    database_baseline     = aws_security_group.database_baseline.id
    lb_to_applications    = aws_security_group.lb_to_applications.id
    monitoring_baseline   = aws_security_group.monitoring_baseline.id
  }
}

output "all_baseline_security_group_names" {
  description = "Map of all baseline security group names"
  value = {
    vpc_endpoints          = aws_security_group.vpc_endpoints.name
    waf_to_nlb            = aws_security_group.waf_to_nlb.name
    eks_cluster_baseline  = aws_security_group.eks_cluster_baseline.name
    database_baseline     = aws_security_group.database_baseline.name
    lb_to_applications    = aws_security_group.lb_to_applications.name
    monitoring_baseline   = aws_security_group.monitoring_baseline.name
  }
}

output "all_prefix_list_ids" {
  description = "Map of all managed prefix list IDs"
  value = {
    corporate_networks   = aws_ec2_managed_prefix_list.corporate_networks.id
    waf_saas_providers  = aws_ec2_managed_prefix_list.waf_saas_providers.id
    aws_vpc_endpoints   = aws_ec2_managed_prefix_list.aws_vpc_endpoints.id
    database_subnets    = aws_ec2_managed_prefix_list.database_subnets.id
    alb_subnets         = aws_ec2_managed_prefix_list.alb_subnets.id
    ci_cd_systems       = aws_ec2_managed_prefix_list.ci_cd_systems.id
    monitoring_services = aws_ec2_managed_prefix_list.monitoring_services.id
  }
}

output "all_prefix_list_arns" {
  description = "Map of all managed prefix list ARNs"
  value = {
    corporate_networks   = aws_ec2_managed_prefix_list.corporate_networks.arn
    waf_saas_providers  = aws_ec2_managed_prefix_list.waf_saas_providers.arn
    aws_vpc_endpoints   = aws_ec2_managed_prefix_list.aws_vpc_endpoints.arn
    database_subnets    = aws_ec2_managed_prefix_list.database_subnets.arn
    alb_subnets         = aws_ec2_managed_prefix_list.alb_subnets.arn
    ci_cd_systems       = aws_ec2_managed_prefix_list.ci_cd_systems.arn
    monitoring_services = aws_ec2_managed_prefix_list.monitoring_services.arn
  }
}

# Resource sharing information
output "prefix_lists_resource_share_arn" {
  description = "ARN of the RAM resource share for prefix lists"
  value       = length(var.share_prefix_lists_with_accounts) > 0 ? aws_ram_resource_share.prefix_lists[0].arn : null
}

output "prefix_lists_resource_share_status" {
  description = "Status of the RAM resource share for prefix lists"
  value       = length(var.share_prefix_lists_with_accounts) > 0 ? aws_ram_resource_share.prefix_lists[0].status : null
}

# Metadata and deployment information
output "deployment_metadata" {
  description = "Metadata about the baseline deployment"
  value = {
    account_id          = var.account_id
    region              = var.region
    vpc_id              = local.vpc_id
    deployment_time     = timestamp()
    terraform_workspace = terraform.workspace
    total_security_groups = 6
    total_prefix_lists    = 7
  }
}

# For use by account-specific configurations
output "baseline_references" {
  description = "Reference information for account-specific security group configurations"
  value = {
    # Security Group references that can be used in source_security_group_id
    security_groups = {
      "baseline-vpc-endpoints"         = aws_security_group.vpc_endpoints.id
      "baseline-waf-to-nlb"           = aws_security_group.waf_to_nlb.id
      "baseline-eks-cluster"          = aws_security_group.eks_cluster_baseline.id
      "baseline-database"             = aws_security_group.database_baseline.id
      "baseline-lb-to-apps"           = aws_security_group.lb_to_applications.id
      "baseline-monitoring"           = aws_security_group.monitoring_baseline.id
    }
    
    # Prefix List references that can be used in prefix_list_ids
    prefix_lists = {
      "corporate-networks"   = aws_ec2_managed_prefix_list.corporate_networks.id
      "waf-saas-providers"  = aws_ec2_managed_prefix_list.waf_saas_providers.id
      "aws-vpc-endpoints"   = aws_ec2_managed_prefix_list.aws_vpc_endpoints.id
      "database-subnets"    = aws_ec2_managed_prefix_list.database_subnets.id
      "alb-subnets"         = aws_ec2_managed_prefix_list.alb_subnets.id
      "ci-cd-systems"       = aws_ec2_managed_prefix_list.ci_cd_systems.id
      "monitoring-services" = aws_ec2_managed_prefix_list.monitoring_services.id
    }
    
    # Network information
    network = {
      vpc_id                  = local.vpc_id
      vpc_cidr               = local.vpc_cidr
      private_subnet_cidrs   = local.private_subnet_cidrs
      public_subnet_cidrs    = local.public_subnet_cidrs
      database_subnet_cidrs  = local.database_subnet_cidrs
    }
  }
}