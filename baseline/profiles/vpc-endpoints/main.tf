# AWS Security Group Platform - VPC Endpoints Profile
#
# Single security group for all VPC interface endpoints.
# Ingress from local VPC CIDR on 443 (and 80 for S3 gateway).
# No egress — endpoint ENIs respond to requests, they don't initiate.
#
# Risk acceptance: All resources in the VPC can reach all endpoints.
# Per-endpoint access control is handled by:
#   1. VPC endpoint policies (resource-level)
#   2. IAM roles on the source workload
# SG-level per-endpoint isolation is not practical (all endpoints share this SG).

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "baseline-vpc-endpoints-"
  description = "VPC endpoints — ingress from local VPC only"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-vpc-endpoints"
    Type    = "baseline"
    Profile = "vpc-endpoints"
  })
}

# HTTPS — all interface endpoints (ECR, STS, CloudWatch, SSM, etc.)
resource "aws_vpc_security_group_ingress_rule" "vpce_https" {
  security_group_id = aws_security_group.vpc_endpoints.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from VPC to interface endpoints"
}

# HTTP — S3 gateway endpoint
resource "aws_vpc_security_group_ingress_rule" "vpce_http" {
  security_group_id = aws_security_group.vpc_endpoints.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP from VPC for S3 gateway endpoint"
}
