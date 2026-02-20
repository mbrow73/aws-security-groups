# AWS Security Group Platform - EKS Standard Profile
# Common security group for EKS cluster communication

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Reference to corporate networks prefix list (created by baseline prefix-lists.tf)
data "aws_ec2_managed_prefix_list" "corporate_networks" {
  name = "corporate-networks"
}

# Get private subnet CIDRs for EKS node communication
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
  
  filter {
    name   = "tag:Name"
    values = ["*private*"]
  }
}

data "aws_subnet" "private" {
  for_each = toset(data.aws_subnets.private.ids)
  id       = each.value
}

locals {
  # Private subnets (usually for applications and EKS nodes)
  private_subnet_cidrs = [
    for subnet in data.aws_subnet.private : subnet.cidr_block
  ]
}

#
# EKS Cluster Baseline Security Group
# Common security group for EKS cluster communication
#
resource "aws_security_group" "eks_cluster_baseline" {
  name_prefix = "baseline-eks-cluster-"
  description = "Baseline security group for EKS cluster communication"
  vpc_id      = var.vpc_id

  # EKS cluster API access from worker nodes and management tools
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.private_subnet_cidrs
    description = "EKS API access from private subnets"
  }

  # EKS cluster API access from corporate networks (for kubectl)
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.corporate_networks.id]
    description     = "EKS API access from corporate networks"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.common_tags, {
    Name        = "baseline-eks-cluster"
    Purpose     = "eks-cluster"
    Type        = "baseline"
    Profile     = "eks-standard"
    Description = "Baseline security group for EKS cluster"
  })
}