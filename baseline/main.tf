# AWS Security Group Platform - Baseline Security Groups
# These security groups are applied to every account and provide common patterns
# used across the organization

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

  # VPC endpoints that require security group access
  vpc_endpoints = [
    "s3",
    "ecr.api",
    "ecr.dkr", 
    "eks",
    "logs",
    "monitoring",
    "ssm",
    "ssmmessages",
    "ec2messages"
  ]
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

# Get subnet information for the VPC
data "aws_subnets" "all" {
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

data "aws_subnet" "selected" {
  for_each = toset(data.aws_subnets.all.ids)
  id       = each.value
}

locals {
  # Group subnets by type (private, public, database, etc.)
  subnet_cidrs = [for subnet in data.aws_subnet.selected : subnet.cidr_block]
  
  # Private subnets (usually for applications)
  private_subnet_cidrs = [
    for subnet in data.aws_subnet.selected : subnet.cidr_block
    if can(regex(".*private.*", lower(subnet.tags["Name"])))
  ]
  
  # Public subnets (usually for load balancers)
  public_subnet_cidrs = [
    for subnet in data.aws_subnet.selected : subnet.cidr_block
    if can(regex(".*public.*", lower(subnet.tags["Name"])))
  ]
  
  # Database subnets
  database_subnet_cidrs = [
    for subnet in data.aws_subnet.selected : subnet.cidr_block
    if can(regex(".*database.*|.*db.*|.*rds.*", lower(subnet.tags["Name"])))
  ]
}

#
# Baseline Security Group 1: VPC Endpoints
# Allows access to AWS VPC endpoints (S3, ECR, EKS API, etc.)
#
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "baseline-vpc-endpoints-"
  description = "Baseline security group for VPC endpoints access"
  vpc_id      = local.vpc_id

  # Ingress rules for VPC endpoint access
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
    description = "HTTPS from VPC for VPC endpoints"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"  
    cidr_blocks = [local.vpc_cidr]
    description = "HTTP from VPC for VPC endpoints (S3)"
  }

  # Allow access to specific VPC endpoint ports
  dynamic "ingress" {
    for_each = var.additional_vpc_endpoint_ports
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = [local.vpc_cidr]
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

  tags = merge(local.common_tags, {
    Name        = "baseline-vpc-endpoints"
    Purpose     = "vpc-endpoints"
    Type        = "baseline"
    Description = "Baseline security group for VPC endpoints access"
  })
}

#
# Baseline Security Group 2: WAF to NLB
# Allows WAF/CDN providers to reach Network Load Balancers
#
resource "aws_security_group" "waf_to_nlb" {
  name_prefix = "baseline-waf-to-nlb-"
  description = "Baseline security group for WAF/CDN to NLB traffic"
  vpc_id      = local.vpc_id

  # HTTP traffic from WAF/CDN providers
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [aws_ec2_managed_prefix_list.waf_saas_providers.id]
    description     = "HTTP from WAF/CDN providers"
  }

  # HTTPS traffic from WAF/CDN providers  
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_ec2_managed_prefix_list.waf_saas_providers.id]
    description     = "HTTPS from WAF/CDN providers"
  }

  # Custom ports for specific applications
  dynamic "ingress" {
    for_each = var.waf_custom_ports
    content {
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      prefix_list_ids = [aws_ec2_managed_prefix_list.waf_saas_providers.id]
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

  tags = merge(local.common_tags, {
    Name        = "baseline-waf-to-nlb"
    Purpose     = "waf-nlb"
    Type        = "baseline"
    Description = "Baseline security group for WAF to NLB traffic"
  })
}

#
# Baseline Security Group 3: EKS Cluster Baseline
# Common security group for EKS cluster communication
#
resource "aws_security_group" "eks_cluster_baseline" {
  name_prefix = "baseline-eks-cluster-"
  description = "Baseline security group for EKS cluster communication"
  vpc_id      = local.vpc_id

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
    prefix_list_ids = [aws_ec2_managed_prefix_list.corporate_networks.id]
    description     = "EKS API access from corporate networks"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name        = "baseline-eks-cluster"
    Purpose     = "eks-cluster"
    Type        = "baseline"
    Description = "Baseline security group for EKS cluster"
  })
}

#
# Baseline Security Group 4: Database Access
# Common patterns for database access (RDS, ElastiCache, etc.)
#
resource "aws_security_group" "database_baseline" {
  name_prefix = "baseline-database-"
  description = "Baseline security group for database access patterns"
  vpc_id      = local.vpc_id

  # MySQL/Aurora access from application subnets
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = local.private_subnet_cidrs
    description = "MySQL/Aurora from application subnets"
  }

  # PostgreSQL access from application subnets
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = local.private_subnet_cidrs
    description = "PostgreSQL from application subnets"
  }

  # Redis access from application subnets
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = local.private_subnet_cidrs
    description = "Redis from application subnets"
  }

  # No egress rules - databases typically don't need outbound access
  
  tags = merge(local.common_tags, {
    Name        = "baseline-database"
    Purpose     = "database"
    Type        = "baseline"
    Description = "Baseline security group for database access"
  })
}

#
# Baseline Security Group 5: Load Balancer to Applications
# Common patterns for ALB/NLB to application communication
#
resource "aws_security_group" "lb_to_applications" {
  name_prefix = "baseline-lb-to-apps-"
  description = "Baseline security group for load balancer to application traffic"
  vpc_id      = local.vpc_id

  # HTTP traffic from ALB/NLB subnets
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = local.public_subnet_cidrs
    description = "HTTP from load balancer subnets"
  }

  # HTTPS traffic from ALB/NLB subnets
  ingress {
    from_port   = 443  
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.public_subnet_cidrs
    description = "HTTPS from load balancer subnets"
  }

  # Common application ports
  dynamic "ingress" {
    for_each = var.common_app_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = local.public_subnet_cidrs
      description = "Port ${ingress.value} from load balancers"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name        = "baseline-lb-to-apps"
    Purpose     = "load-balancer"
    Type        = "baseline"
    Description = "Baseline security group for load balancer to applications"
  })
}

#
# Baseline Security Group 6: Monitoring and Logging
# Access patterns for monitoring tools, log shipping, etc.
#
resource "aws_security_group" "monitoring_baseline" {
  name_prefix = "baseline-monitoring-"
  description = "Baseline security group for monitoring and logging access"
  vpc_id      = local.vpc_id

  # Prometheus/monitoring scraping
  ingress {
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = local.private_subnet_cidrs
    description = "Node Exporter metrics"
  }

  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = local.private_subnet_cidrs
    description = "Prometheus server"
  }

  # Custom application metrics ports
  dynamic "ingress" {
    for_each = var.monitoring_ports
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = local.private_subnet_cidrs
      description = "Custom monitoring port ${ingress.value}"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic for log shipping"
  }

  tags = merge(local.common_tags, {
    Name        = "baseline-monitoring"
    Purpose     = "monitoring"
    Type        = "baseline"
    Description = "Baseline security group for monitoring and logging"
  })
}