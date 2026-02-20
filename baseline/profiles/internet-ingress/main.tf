# AWS Security Group Platform - Internet Ingress Profile
# Allows WAF/CDN providers to reach Network Load Balancers

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Reference to WAF SaaS providers prefix list (created by baseline prefix-lists.tf)
data "aws_ec2_managed_prefix_list" "waf_saas_providers" {
  name = "waf-saas-providers"
}

#
# WAF to NLB Security Group
# Allows WAF/CDN providers to reach Network Load Balancers
#
resource "aws_security_group" "waf_to_nlb" {
  name_prefix = "baseline-waf-to-nlb-"
  description = "Baseline security group for WAF/CDN to NLB traffic"
  vpc_id      = var.vpc_id

  # HTTP traffic from WAF/CDN providers
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.waf_saas_providers.id]
    description     = "HTTP from WAF/CDN providers"
  }

  # HTTPS traffic from WAF/CDN providers  
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.waf_saas_providers.id]
    description     = "HTTPS from WAF/CDN providers"
  }

  # Custom ports for specific applications
  dynamic "ingress" {
    for_each = var.waf_custom_ports
    content {
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      prefix_list_ids = [data.aws_ec2_managed_prefix_list.waf_saas_providers.id]
      description     = "Custom port ${ingress.value} from WAF/CDN"
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
    Name        = "baseline-waf-to-nlb"
    Purpose     = "waf-nlb"
    Type        = "baseline"
    Profile     = "internet-ingress"
    Description = "Baseline security group for WAF to NLB traffic"
  })
}