# Tests for VPC Endpoints baseline profile
# Run from baseline/profiles/vpc-endpoints: terraform test

mock_provider "aws" {}

variables {
  vpc_id     = "vpc-0123456789abcdef0"
  vpc_cidr   = "10.0.0.0/16"
  account_id = "123456789012"
  common_tags = {
    Environment = "test"
    ManagedBy   = "sg-platform"
  }
}

# --------------------------------------------------
# Test: Single SG created with correct tags
# --------------------------------------------------
run "creates_one_sg" {
  command = plan

  assert {
    condition     = aws_security_group.vpc_endpoints.vpc_id == "vpc-0123456789abcdef0"
    error_message = "VPC endpoints SG not in correct VPC"
  }

  assert {
    condition     = aws_security_group.vpc_endpoints.tags["Type"] == "baseline"
    error_message = "Should have Type=baseline tag"
  }

  assert {
    condition     = aws_security_group.vpc_endpoints.tags["Profile"] == "vpc-endpoints"
    error_message = "Should have Profile=vpc-endpoints tag"
  }
}

# --------------------------------------------------
# Test: Ingress from VPC CIDR on correct ports
# --------------------------------------------------
run "ingress_rules" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.vpce_https.cidr_ipv4 == "10.0.0.0/16"
    error_message = "HTTPS ingress should use VPC CIDR"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.vpce_https.from_port == 443
    error_message = "HTTPS ingress should be port 443"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.vpce_http.from_port == 80
    error_message = "HTTP ingress should be port 80"
  }
}
