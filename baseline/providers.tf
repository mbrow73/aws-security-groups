# Provider configuration — credentials via TFC workspace variables or environment

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      ManagedBy  = "sg-platform"
      Module     = "baseline"
      Account    = var.account_id
      Repository = "aws-security-groups"
    }
  }
}
