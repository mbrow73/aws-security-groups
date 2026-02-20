# AWS Security Group Platform - Managed Prefix Lists
# Creates AWS Managed Prefix Lists from the centralized configuration

# Load prefix lists configuration from YAML
locals {
  # Load prefix lists from the root configuration file
  prefix_lists_config = yamldecode(file("${path.root}/../prefix-lists.yaml"))
  
  # Extract prefix lists and apply regional overrides if they exist
  prefix_lists = merge(
    local.prefix_lists_config.prefix_lists,
    lookup(
      lookup(local.prefix_lists_config, "regional_overrides", {}),
      var.region,
      {}
    )
  )
}

#
# Corporate Networks Prefix List
#
resource "aws_ec2_managed_prefix_list" "corporate_networks" {
  name           = local.prefix_lists.corporate-networks.name
  address_family = local.prefix_lists.corporate-networks.address_family
  max_entries    = local.prefix_lists.corporate-networks.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.corporate-networks.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.corporate-networks.tags, {
    Name = local.prefix_lists.corporate-networks.name
  })
}

#
# WAF/SaaS Providers Prefix List
#
resource "aws_ec2_managed_prefix_list" "waf_saas_providers" {
  name           = local.prefix_lists.waf-saas-providers.name
  address_family = local.prefix_lists.waf-saas-providers.address_family
  max_entries    = local.prefix_lists.waf-saas-providers.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.waf-saas-providers.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.waf-saas-providers.tags, {
    Name = local.prefix_lists.waf-saas-providers.name
  })
}

#
# AWS VPC Endpoints Prefix List
#
resource "aws_ec2_managed_prefix_list" "aws_vpc_endpoints" {
  name           = local.prefix_lists.aws-vpc-endpoints.name
  address_family = local.prefix_lists.aws-vpc-endpoints.address_family
  max_entries    = local.prefix_lists.aws-vpc-endpoints.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.aws-vpc-endpoints.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.aws-vpc-endpoints.tags, {
    Name = local.prefix_lists.aws-vpc-endpoints.name
  })
}

#
# Database Subnets Prefix List
#
resource "aws_ec2_managed_prefix_list" "database_subnets" {
  name           = local.prefix_lists.database-subnets.name
  address_family = local.prefix_lists.database-subnets.address_family
  max_entries    = local.prefix_lists.database-subnets.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.database-subnets.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.database-subnets.tags, {
    Name = local.prefix_lists.database-subnets.name
  })
}

#
# ALB Subnets Prefix List
#
resource "aws_ec2_managed_prefix_list" "alb_subnets" {
  name           = local.prefix_lists.alb-subnets.name
  address_family = local.prefix_lists.alb-subnets.address_family
  max_entries    = local.prefix_lists.alb-subnets.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.alb-subnets.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.alb-subnets.tags, {
    Name = local.prefix_lists.alb-subnets.name
  })
}

#
# CI/CD Systems Prefix List
#
resource "aws_ec2_managed_prefix_list" "ci_cd_systems" {
  name           = local.prefix_lists.ci-cd-systems.name
  address_family = local.prefix_lists.ci-cd-systems.address_family
  max_entries    = local.prefix_lists.ci-cd-systems.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.ci-cd-systems.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.ci-cd-systems.tags, {
    Name = local.prefix_lists.ci-cd-systems.name
  })
}

#
# Monitoring Services Prefix List
#
resource "aws_ec2_managed_prefix_list" "monitoring_services" {
  name           = local.prefix_lists.monitoring-services.name
  address_family = local.prefix_lists.monitoring-services.address_family
  max_entries    = local.prefix_lists.monitoring-services.max_entries

  dynamic "entry" {
    for_each = local.prefix_lists.monitoring-services.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(local.common_tags, local.prefix_lists.monitoring-services.tags, {
    Name = local.prefix_lists.monitoring-services.name
  })
}

#
# Prefix List Sharing (if needed for cross-account access)
#
resource "aws_ram_resource_share" "prefix_lists" {
  count                     = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  name                      = "security-groups-prefix-lists-${var.account_id}"
  allow_external_principals = false

  tags = merge(local.common_tags, {
    Name        = "sg-platform-prefix-lists"
    Purpose     = "cross-account-sharing"
    Description = "Share prefix lists across accounts"
  })
}

# Associate prefix lists with the resource share
resource "aws_ram_resource_association" "corporate_networks" {
  count              = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  resource_arn       = aws_ec2_managed_prefix_list.corporate_networks.arn
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

resource "aws_ram_resource_association" "waf_saas_providers" {
  count              = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  resource_arn       = aws_ec2_managed_prefix_list.waf_saas_providers.arn
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

resource "aws_ram_resource_association" "aws_vpc_endpoints" {
  count              = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  resource_arn       = aws_ec2_managed_prefix_list.aws_vpc_endpoints.arn
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

resource "aws_ram_resource_association" "database_subnets" {
  count              = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  resource_arn       = aws_ec2_managed_prefix_list.database_subnets.arn
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

resource "aws_ram_resource_association" "alb_subnets" {
  count              = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  resource_arn       = aws_ec2_managed_prefix_list.alb_subnets.arn
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

resource "aws_ram_resource_association" "ci_cd_systems" {
  count              = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  resource_arn       = aws_ec2_managed_prefix_list.ci_cd_systems.arn
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

resource "aws_ram_resource_association" "monitoring_services" {
  count              = length(var.share_prefix_lists_with_accounts) > 0 ? 1 : 0
  resource_arn       = aws_ec2_managed_prefix_list.monitoring_services.arn
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}

# Invite target accounts to the resource share
resource "aws_ram_principal_association" "accounts" {
  count              = length(var.share_prefix_lists_with_accounts)
  principal          = var.share_prefix_lists_with_accounts[count.index]
  resource_share_arn = aws_ram_resource_share.prefix_lists[0].arn
}