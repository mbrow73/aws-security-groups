# Root Configuration — SG Self-Service Platform
#
# Each TFE workspace is named `sg-<account_id>`. The account ID is
# derived from the workspace name — no variables need to be set.
# Dynamic credentials are scoped per account at workspace creation
# via CloudIaC API (Vault-backed, account-scoped — works across regions).
#
# Multi-region: SGs declare a region (or inherit default_region).
# Provider aliases are pre-declared per supported region. Each region
# gets its own module call with the appropriate provider.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ---------------------------------------------------------------------------
# Provider Aliases — one per supported region
# Vault-backed dynamic creds are account-scoped (not region-scoped),
# so all providers inherit the same credentials automatically.
# ---------------------------------------------------------------------------

provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"
}

# ---------------------------------------------------------------------------
# Locals — parse YAML, resolve regions, group SGs
# ---------------------------------------------------------------------------

locals {
  # Derive account_id from workspace name
  # Supports both formats:
  #   - "sg-123456789012"                  (local / direct)
  #   - "<car_id>-<env>-sg-123456789012"   (CloudIaC provisioned)
  account_id = regex("sg-(\\d{12})$", terraform.workspace)[0]

  # Read account YAML
  config = yamldecode(file("${path.root}/accounts/${local.account_id}/security-groups.yaml"))

  # Account-level defaults
  default_region = lookup(local.config, "default_region", "us-east-1")
  environment    = lookup(local.config, "environment", "unknown")
  carid          = tostring(local.config.carid)

  # Resolve each SG's region (explicit or default)
  security_groups = {
    for name, sg in lookup(local.config, "security_groups", {}) :
    name => merge(sg, {
      _region = lookup(sg, "region", local.default_region)
    })
  }

  # Group SGs by region
  sgs_by_region = {
    for r in distinct([for sg in local.security_groups : sg._region]) :
    r => {
      for name, sg in local.security_groups :
      name => sg if sg._region == r
    }
  }

  # Corporate mandatory tags
  corporate_mandatory_tags = {
    "<company>-app-env"               = local.environment
    "<company>-data-classification"   = "internal"
    "<company>-app-carid"             = local.carid
    "<company>-ops-supportgroup"      = "Security_Operations_Support"
    "<company>-app-supportgroup"      = "Security_Operations_Support"
    "<company>-provisioner-repo"      = "placeholder"
    "<company>-iam-access-control"    = "netsec"
    "<company>-provisioner-workspace" = "${local.carid}-${local.environment}-sg-${local.account_id}"
  }

  # Platform-managed tags
  platform_tags = {
    ManagedBy   = "sg-platform"
    Account     = local.account_id
    Environment = local.environment
    Repository  = "aws-security-groups"
  }

  # All tags merged
  common_tags = merge(
    local.platform_tags,
    local.corporate_mandatory_tags,
    lookup(local.config, "tags", {})
  )
}

variable "prefix_list_mappings" {
  description = "Map of prefix list friendly names to AWS prefix list IDs"
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Baseline Ref Allowlist
# Only these baseline SG names can be referenced via baseline_ref in YAML.
# Expanding this list is a deliberate security decision.
# ---------------------------------------------------------------------------

locals {
  # Scan all SGs for baseline_ref usage and collect unique refs
  baseline_refs_used = distinct(flatten([
    for sg_name, sg in local.security_groups : concat(
      [for rule in lookup(sg, "ingress", []) : lookup(rule, "baseline_ref", null) if lookup(rule, "baseline_ref", null) != null],
      [for rule in lookup(sg, "egress", []) : lookup(rule, "baseline_ref", null) if lookup(rule, "baseline_ref", null) != null]
    )
  ]))

  # Allowlist — only these baseline refs are permitted
  baseline_ref_allowlist = ["vpc-endpoints"]

  # AWS-managed prefix list aliases by region.
  # Lets requesters use friendly names like "s3" and "dynamodb"
  # while still resolving to the correct regional managed prefix list ID.
  aws_managed_prefix_list_mappings_by_region = {
    "us-east-1" = {
      dynamodb = "pl-02cd2c6b"
      s3       = "pl-63a5400a"
    }
    "us-west-2" = {
      dynamodb = "pl-00a54069"
      s3       = "pl-68a54001"
    }
  }

  # Shared repo-managed prefix lists — created by this repo in each account/region
  shared_prefix_lists_config = fileexists("${path.root}/shared-prefix-lists.yaml") ? yamldecode(file("${path.root}/shared-prefix-lists.yaml")) : { shared_prefix_lists = {} }
  shared_prefix_lists = lookup(local.shared_prefix_lists_config, "shared_prefix_lists", {})

  # Expand shared prefix lists into per-region instances while keeping the same reference name.
  # Supports either:
  #   region: us-east-1
  # or
  #   regions: [us-east-1, us-west-2]
  shared_prefix_lists_expanded = merge(
    {},
    [
      for name, pl in local.shared_prefix_lists : {
        for region in lookup(pl, "regions", [lookup(pl, "region", "us-east-1")]) :
        "${name}:${region}" => merge(pl, {
          name    = name
          _region = region
        })
      }
    ]...
  )

  shared_prefix_lists_by_region = {
    for r in distinct([for pl in values(local.shared_prefix_lists_expanded) : pl._region]) :
    r => {
      for key, pl in local.shared_prefix_lists_expanded :
      pl.name => pl if pl._region == r
    }
  }
}

# ---------------------------------------------------------------------------
# Region Module Calls — one per supported region
# ---------------------------------------------------------------------------

module "us_east_1" {
  source = "./modules/account"
  count  = contains(keys(local.sgs_by_region), "us-east-1") ? 1 : 0

  providers = {
    aws = aws.us-east-1
  }

  security_groups        = lookup(local.sgs_by_region, "us-east-1", {})
  account_id             = local.account_id
  tags                   = local.common_tags
  prefix_list_mappings = merge(
    var.prefix_list_mappings,
    lookup(local.aws_managed_prefix_list_mappings_by_region, "us-east-1", {})
  )
  baseline_ref_allowlist = local.baseline_ref_allowlist
  shared_prefix_lists    = lookup(local.shared_prefix_lists_by_region, "us-east-1", {})
}

module "us_west_2" {
  source = "./modules/account"
  count  = contains(keys(local.sgs_by_region), "us-west-2") ? 1 : 0

  providers = {
    aws = aws.us-west-2
  }

  security_groups        = lookup(local.sgs_by_region, "us-west-2", {})
  account_id             = local.account_id
  tags                   = local.common_tags
  prefix_list_mappings = merge(
    var.prefix_list_mappings,
    lookup(local.aws_managed_prefix_list_mappings_by_region, "us-west-2", {})
  )
  baseline_ref_allowlist = local.baseline_ref_allowlist
  shared_prefix_lists    = lookup(local.shared_prefix_lists_by_region, "us-west-2", {})
}

# ---------------------------------------------------------------------------
# Outputs — merged across all regions
# ---------------------------------------------------------------------------

output "security_group_ids" {
  description = "Map of SG name to SG ID for this account (all regions)"
  value = merge(
    length(module.us_east_1) > 0 ? module.us_east_1[0].security_group_ids : {},
    length(module.us_west_2) > 0 ? module.us_west_2[0].security_group_ids : {},
  )
}

output "account_id" {
  description = "The account ID this workspace manages"
  value       = local.account_id
}
