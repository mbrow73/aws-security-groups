# Tests for EKS Internet baseline profile
# Run from baseline/profiles/eks-internet: terraform test

mock_provider "aws" {}

variables {
  vpc_id              = "vpc-0123456789abcdef0"
  vpc_endpoints_sg_id = "sg-vpce0123456789abc"
  account_id          = "123456789012"
  common_tags = {
    Environment = "test"
    ManagedBy   = "sg-platform"
  }
}

# --------------------------------------------------
# Test: All 6 security groups are created
# --------------------------------------------------
run "creates_six_security_groups" {
  command = plan

  assert {
    condition     = aws_security_group.eks_cluster.vpc_id == "vpc-0123456789abcdef0"
    error_message = "EKS cluster SG not created"
  }

  assert {
    condition     = aws_security_group.eks_workers.vpc_id == "vpc-0123456789abcdef0"
    error_message = "EKS workers SG not created"
  }

  assert {
    condition     = aws_security_group.istio_intranet_nodes.vpc_id == "vpc-0123456789abcdef0"
    error_message = "Istio intranet SG not created"
  }

  assert {
    condition     = aws_security_group.intranet_nlb.vpc_id == "vpc-0123456789abcdef0"
    error_message = "Intranet NLB SG not created"
  }

  assert {
    condition     = aws_security_group.istio_inet_nodes.vpc_id == "vpc-0123456789abcdef0"
    error_message = "Istio internet SG not created"
  }

  assert {
    condition     = aws_security_group.internet_nlb.vpc_id == "vpc-0123456789abcdef0"
    error_message = "Internet NLB SG not created"
  }
}

# --------------------------------------------------
# Test: Workers accept mesh from BOTH istio paths
# --------------------------------------------------
run "workers_dual_istio_ingress" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.workers_from_istio_intranet_15006.from_port == 15006
    error_message = "Workers should accept 15006 from intranet istio"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.workers_from_istio_inet_15006.from_port == 15006
    error_message = "Workers should accept 15006 from internet istio"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.workers_from_istio_intranet_15012.from_port == 15012
    error_message = "Workers should accept 15012 from intranet istio"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.workers_from_istio_inet_15012.from_port == 15012
    error_message = "Workers should accept 15012 from internet istio"
  }
}

# --------------------------------------------------
# Test: Cluster serves both istio node groups
# --------------------------------------------------
run "cluster_dual_istio" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.cluster_from_istio_intranet_443.from_port == 443
    error_message = "Cluster should accept 443 from intranet istio"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.cluster_from_istio_inet_443.from_port == 443
    error_message = "Cluster should accept 443 from internet istio"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.cluster_to_istio_intranet_10250.from_port == 10250
    error_message = "Cluster should egress 10250 to intranet istio"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.cluster_to_istio_inet_10250.from_port == 10250
    error_message = "Cluster should egress 10250 to internet istio"
  }
}

# --------------------------------------------------
# Test: Internet istio uses prefix list (WAF NAT IPs)
# --------------------------------------------------
run "inet_istio_uses_prefix_list" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_ingress_rule.istio_inet_from_waf_8443.from_port == 8443
    error_message = "Internet istio should have 8443 ingress"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.internet_nlb_from_waf_443.from_port == 443
    error_message = "Internet NLB should have 443 ingress"
  }
}

# --------------------------------------------------
# Test: Workers on-prem egress
# --------------------------------------------------
run "workers_onprem_egress" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.workers_to_onprem_443.from_port == 443
    error_message = "Workers should have egress 443 to on-prem"
  }
}

# --------------------------------------------------
# Test: Correct profile tags
# --------------------------------------------------
run "correct_tags" {
  command = plan

  assert {
    condition     = aws_security_group.eks_cluster.tags["Profile"] == "eks-internet"
    error_message = "Should be tagged eks-internet"
  }

  assert {
    condition     = aws_security_group.istio_inet_nodes.tags["Profile"] == "eks-internet"
    error_message = "Internet istio should be tagged eks-internet"
  }

  assert {
    condition     = aws_security_group.istio_intranet_nodes.tags["Profile"] == "eks-internet"
    error_message = "Intranet istio should be tagged eks-internet"
  }
}
