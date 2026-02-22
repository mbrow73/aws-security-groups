# AWS Security Group Platform - Baseline Security Groups
# Conditional deployment of baseline security group profiles based on account configuration

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
  # Standard tags applied to all resources
  common_tags = merge(var.tags, {
    ManagedBy   = "sg-platform"
    Module      = "baseline"
    Account     = var.account_id
    Repository  = "aws-security-groups"
  })

  # Convert profile list to set for easier lookup
  enabled_profiles = toset(var.baseline_profiles)

  # Check if specific profiles are enabled
  # eks-standard implicitly requires vpc-endpoints — auto-enable it
  enable_vpc_endpoints    = contains(local.enabled_profiles, "vpc-endpoints") || contains(local.enabled_profiles, "eks-standard")
  enable_internet_ingress = contains(local.enabled_profiles, "internet-ingress")
  enable_eks_standard     = contains(local.enabled_profiles, "eks-standard")
}

# Data source to get VPC information if not provided
data "aws_vpc" "main" {
  count = var.vpc_id == "auto" ? 1 : 0
  
  filter {
    name   = "state"
    values = ["available"]
  }

  # If multiple VPCs exist, prefer the one tagged as 'main' or 'default'
  filter {
    name   = "tag:Name"
    values = ["*main*", "*default*", "*primary*"]
  }
}

data "aws_vpc" "selected" {
  count = var.vpc_id != "auto" ? 1 : 0
  id    = var.vpc_id
}

# Use the discovered or selected VPC
locals {
  vpc_id   = var.vpc_id == "auto" ? data.aws_vpc.main[0].id : data.aws_vpc.selected[0].id
  vpc_cidr = var.vpc_id == "auto" ? data.aws_vpc.main[0].cidr_block : data.aws_vpc.selected[0].cidr_block
}

#
# Baseline Profile Modules - Conditionally deployed based on configuration
#

# VPC Endpoints Profile
module "vpc_endpoints" {
  count  = local.enable_vpc_endpoints ? 1 : 0
  source = "./profiles/vpc-endpoints"

  vpc_id      = local.vpc_id
  vpc_cidr    = local.vpc_cidr
  account_id  = var.account_id
  common_tags = local.common_tags

  additional_vpc_endpoint_ports = var.additional_vpc_endpoint_ports
}

# Internet Ingress Profile (WAF → NLB)
module "internet_ingress" {
  count  = local.enable_internet_ingress ? 1 : 0
  source = "./profiles/internet-ingress"

  vpc_id      = local.vpc_id
  account_id  = var.account_id
  common_tags = local.common_tags

  waf_custom_ports = var.waf_custom_ports
}

# EKS Standard Profile
# Depends on vpc-endpoints for SG chaining (auto-enabled above)
module "eks_standard" {
  count  = local.enable_eks_standard ? 1 : 0
  source = "./profiles/eks-standard"

  vpc_id              = local.vpc_id
  vpc_endpoints_sg_id = module.vpc_endpoints[0].vpc_endpoints_security_group_id
  account_id          = var.account_id
  common_tags         = local.common_tags
}