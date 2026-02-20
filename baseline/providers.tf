# AWS Security Group Platform - Baseline Module Providers Configuration

terraform {
  required_version = ">= 1.6"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    
    # For YAML processing
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    
    # For RAM resource sharing
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

# AWS Provider Configuration
provider "aws" {
  region = var.region

  # Standard tags applied to all resources
  default_tags {
    tags = {
      ManagedBy    = "sg-platform"
      Module       = "baseline"
      Account      = var.account_id
      Environment  = var.environment
      Repository   = "aws-security-groups"
      TerraformWorkspace = terraform.workspace
    }
  }

  # Provider-level configuration for enhanced security
  assume_role {
    # This will be configured via environment variables or AWS credentials
    # when running in GitHub Actions or locally
    role_arn = null
  }

  # Retry configuration for API rate limiting
  retry_mode = "adaptive"

  # S3 configuration for backend operations
  s3_use_path_style           = false
  skip_credentials_validation = false
  skip_metadata_api_check     = false
  skip_region_validation      = false

  # Security configuration
  skip_requesting_account_id  = false
  skip_get_ec2_platforms     = false

  # Maximum number of concurrent operations
  max_retries = 10
}

# Local provider for file processing
provider "local" {}

# Time provider for timestamps and delays
provider "time" {}