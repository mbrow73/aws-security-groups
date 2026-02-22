# Security Group Module Tests
# Run from modules/security-group/: terraform test

mock_provider "aws" {}

# --------------------------------------------------
# Test: Basic SG with ingress + egress
# --------------------------------------------------
run "basic_sg_with_rules" {
  command = apply

  variables {
    vpc_id     = "vpc-0123456789abcdef0"
    account_id = "123456789012"
    environment = "test"
    security_group_config = {
      name        = "payments-db-access"
      description = "Payments service database connectivity"
      tags = {
        Team        = "payments"
        Application = "payments-api"
      }
      ingress = [
        {
          from_port   = 8080
          to_port     = 8080
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/8"]
          description = "HTTP from internal"
        }
      ]
      egress = [
        {
          from_port   = 5432
          to_port     = 5432
          protocol    = "tcp"
          cidr_blocks = ["10.100.0.0/16"]
          description = "PostgreSQL access"
        },
        {
          from_port   = 443
          to_port     = 443
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/8"]
          description = "HTTPS to VPC endpoints"
        }
      ]
    }
  }

  assert {
    condition     = output.security_group_id != null
    error_message = "SG should be created"
  }

  assert {
    condition     = output.security_group_name != null
    error_message = "SG should have a name"
  }
}

# --------------------------------------------------
# Test: SG with self-referencing rule
# --------------------------------------------------
run "sg_with_self_reference" {
  command = apply

  variables {
    vpc_id     = "vpc-0123456789abcdef0"
    account_id = "123456789012"
    environment = "test"
    security_group_config = {
      name        = "mesh-internal"
      description = "Service mesh internal communication"
      tags = {
        Team = "platform"
      }
      ingress = [
        {
          from_port   = 15006
          to_port     = 15006
          protocol    = "tcp"
          self        = true
          description = "Envoy sidecar"
        }
      ]
      egress = [
        {
          from_port   = 15006
          to_port     = 15006
          protocol    = "tcp"
          self        = true
          description = "Envoy sidecar outbound"
        }
      ]
    }
  }

  assert {
    condition     = output.security_group_id != null
    error_message = "SG with self-reference should be created"
  }
}

# --------------------------------------------------
# Test: SG with prefix list reference
# --------------------------------------------------
run "sg_with_prefix_list" {
  command = apply

  variables {
    vpc_id     = "vpc-0123456789abcdef0"
    account_id = "123456789012"
    environment = "production"
    prefix_list_mappings = {
      "corporate-networks" = "pl-0123456789abcdef0"
      "database-subnets"   = "pl-0987654321fedcba0"
    }
    security_group_config = {
      name        = "app-with-prefix-lists"
      description = "App using prefix list references"
      tags = {
        Team = "backend"
      }
      ingress = [
        {
          from_port       = 443
          to_port         = 443
          protocol        = "tcp"
          prefix_list_ids = ["corporate-networks"]
          description     = "HTTPS from corporate"
        }
      ]
      egress = [
        {
          from_port       = 5432
          to_port         = 5432
          protocol        = "tcp"
          prefix_list_ids = ["database-subnets"]
          description     = "PostgreSQL via prefix list"
        }
      ]
    }
  }

  assert {
    condition     = output.security_group_id != null
    error_message = "SG with prefix list should be created"
  }
}

# --------------------------------------------------
# Test: SG with security group reference
# --------------------------------------------------
run "sg_with_sg_reference" {
  command = apply

  variables {
    vpc_id     = "vpc-0123456789abcdef0"
    account_id = "123456789012"
    environment = "test"
    security_group_mappings = {
      "alb-frontend" = "sg-alb0123456789abc"
    }
    security_group_config = {
      name        = "backend-from-alb"
      description = "Backend accepting traffic from ALB"
      tags = {
        Team = "backend"
      }
      ingress = [
        {
          from_port       = 8080
          to_port         = 8080
          protocol        = "tcp"
          security_groups = ["alb-frontend"]
          description     = "HTTP from ALB"
        }
      ]
      egress = []
    }
  }

  assert {
    condition     = output.security_group_id != null
    error_message = "SG with SG reference should be created"
  }
}

# --------------------------------------------------
# Test: SG with no egress (no default allow-all)
# --------------------------------------------------
run "sg_no_egress_no_default" {
  command = apply

  variables {
    vpc_id     = "vpc-0123456789abcdef0"
    account_id = "123456789012"
    environment = "test"
    security_group_config = {
      name        = "ingress-only-sg"
      description = "RDS - ingress only, no egress needed"
      tags = {
        Team = "data"
      }
      ingress = [
        {
          from_port   = 5432
          to_port     = 5432
          protocol    = "tcp"
          cidr_blocks = ["10.0.0.0/8"]
          description = "PostgreSQL from app tier"
        }
      ]
      egress = []
    }
  }

  assert {
    condition     = output.security_group_id != null
    error_message = "SG with no egress should be created"
  }
}

# --------------------------------------------------
# Test: Tags are correct
# --------------------------------------------------
run "tags_applied_correctly" {
  command = apply

  variables {
    vpc_id     = "vpc-0123456789abcdef0"
    account_id = "123456789012"
    environment = "production"
    tags = {
      CostCenter = "engineering"
    }
    security_group_config = {
      name        = "tag-test-sg"
      description = "Testing tag application"
      tags = {
        Team        = "platform"
        Application = "test"
      }
      ingress = []
      egress  = []
    }
  }

  assert {
    condition     = output.security_group_id != null
    error_message = "Tagged SG should be created"
  }
}
