# AWS Security Group Platform - VPC Endpoints Profile
# Provides security groups for VPC endpoint access patterns

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

#
# VPC Endpoints Security Group
# Allows access to AWS VPC endpoints (S3, ECR, EKS API, etc.)
#
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "baseline-vpc-endpoints-"
  description = "Baseline security group for VPC endpoints access"
  vpc_id      = var.vpc_id

  # Ingress rules for VPC endpoint access
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS from VPC for VPC endpoints"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"  
    cidr_blocks = [var.vpc_cidr]
    description = "HTTP from VPC for VPC endpoints (S3)"
  }

  # Allow access to specific VPC endpoint ports
  dynamic "ingress" {
    for_each = var.additional_vpc_endpoint_ports
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
      description = "Access to ${ingress.value.service} VPC endpoint"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.common_tags, {
    Name        = "baseline-vpc-endpoints"
    Purpose     = "vpc-endpoints"
    Type        = "baseline"
    Profile     = "vpc-endpoints"
    Description = "Baseline security group for VPC endpoints access"
  })
}