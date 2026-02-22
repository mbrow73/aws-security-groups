# AWS Security Group Platform - Baseline Module Outputs

# VPC Information
output "vpc_id" {
  description = "ID of the VPC where security groups were created"
  value       = local.vpc_id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = local.vpc_cidr
}

# Enabled Profiles
output "enabled_baseline_profiles" {
  description = "List of enabled baseline profiles"
  value       = var.baseline_profiles
}

# VPC Endpoints Profile Outputs
output "vpc_endpoints_security_group_id" {
  description = "ID of the VPC endpoints security group (if enabled)"
  value       = length(module.vpc_endpoints) > 0 ? module.vpc_endpoints[0].vpc_endpoints_security_group_id : null
}

# EKS Internet Profile Outputs
output "inet_eks_cluster_security_group_id" {
  description = "ID of the EKS cluster control plane SG (eks-internet, if enabled)"
  value       = length(module.eks_internet) > 0 ? module.eks_internet[0].eks_cluster_security_group_id : null
}

output "inet_eks_workers_security_group_id" {
  description = "ID of the EKS worker nodes SG (eks-internet, if enabled)"
  value       = length(module.eks_internet) > 0 ? module.eks_internet[0].eks_workers_security_group_id : null
}

output "inet_istio_intranet_nodes_security_group_id" {
  description = "ID of the intranet istio nodes SG (eks-internet, if enabled)"
  value       = length(module.eks_internet) > 0 ? module.eks_internet[0].istio_intranet_nodes_security_group_id : null
}

output "inet_intranet_nlb_security_group_id" {
  description = "ID of the intranet NLB SG (eks-internet, if enabled)"
  value       = length(module.eks_internet) > 0 ? module.eks_internet[0].intranet_nlb_security_group_id : null
}

output "inet_istio_inet_nodes_security_group_id" {
  description = "ID of the internet istio nodes SG (eks-internet, if enabled)"
  value       = length(module.eks_internet) > 0 ? module.eks_internet[0].istio_inet_nodes_security_group_id : null
}

output "inet_internet_nlb_security_group_id" {
  description = "ID of the internet NLB SG (eks-internet, if enabled)"
  value       = length(module.eks_internet) > 0 ? module.eks_internet[0].internet_nlb_security_group_id : null
}

# EKS Standard Profile Outputs
output "eks_cluster_security_group_id" {
  description = "ID of the EKS cluster control plane security group (if enabled)"
  value       = length(module.eks_standard) > 0 ? module.eks_standard[0].eks_cluster_security_group_id : null
}

output "eks_workers_security_group_id" {
  description = "ID of the EKS worker nodes security group (if enabled)"
  value       = length(module.eks_standard) > 0 ? module.eks_standard[0].eks_workers_security_group_id : null
}

output "istio_nodes_security_group_id" {
  description = "ID of the istio dedicated gateway nodes security group (if enabled)"
  value       = length(module.eks_standard) > 0 ? module.eks_standard[0].istio_nodes_security_group_id : null
}

output "intranet_nlb_security_group_id" {
  description = "ID of the intranet NLB security group (if enabled)"
  value       = length(module.eks_standard) > 0 ? module.eks_standard[0].intranet_nlb_security_group_id : null
}

# Prefix Lists (still global)
output "prefix_lists" {
  description = "Information about managed prefix lists"
  value = {
    corporate_networks    = aws_ec2_managed_prefix_list.corporate_networks.id
    waf_saas_providers   = aws_ec2_managed_prefix_list.waf_saas_providers.id
    aws_vpc_endpoints    = aws_ec2_managed_prefix_list.aws_vpc_endpoints.id
    database_subnets     = aws_ec2_managed_prefix_list.database_subnets.id
    alb_subnets          = aws_ec2_managed_prefix_list.alb_subnets.id
    ci_cd_systems        = aws_ec2_managed_prefix_list.ci_cd_systems.id
    monitoring_services  = aws_ec2_managed_prefix_list.monitoring_services.id
  }
}