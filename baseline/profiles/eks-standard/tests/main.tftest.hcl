# Tests for EKS Standard baseline profile
# Run from baseline/profiles/eks-standard: terraform test

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
# Test: All 4 security groups are created
# --------------------------------------------------
run "creates_four_security_groups" {
  command = plan

  assert {
    condition     = aws_security_group.eks_cluster.vpc_id == "vpc-0123456789abcdef0"
    error_message = "EKS cluster SG not created in correct VPC"
  }

  assert {
    condition     = aws_security_group.eks_workers.vpc_id == "vpc-0123456789abcdef0"
    error_message = "EKS workers SG not created in correct VPC"
  }

  assert {
    condition     = aws_security_group.istio_nodes.vpc_id == "vpc-0123456789abcdef0"
    error_message = "Istio nodes SG not created in correct VPC"
  }

  assert {
    condition     = aws_security_group.intranet_nlb.vpc_id == "vpc-0123456789abcdef0"
    error_message = "Intranet NLB SG not created in correct VPC"
  }
}

# --------------------------------------------------
# Test: Cluster egress ports are correct
# --------------------------------------------------
run "cluster_egress_ports" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.cluster_to_workers_10250.from_port == 10250
    error_message = "Cluster should egress 10250 to workers"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.cluster_to_workers_443.from_port == 443
    error_message = "Cluster should egress 443 to workers (webhooks)"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.cluster_to_workers_15017.from_port == 15017
    error_message = "Cluster should egress 15017 to workers (sidecar injection)"
  }
}

# --------------------------------------------------
# Test: Workers egress to VPC endpoints on 443
# --------------------------------------------------
run "workers_vpce_egress" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.workers_to_vpce_443.from_port == 443
    error_message = "Workers should egress 443 to VPC endpoints"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.workers_to_vpce_443.ip_protocol == "tcp"
    error_message = "Workers VPCE egress should be TCP"
  }
}

# --------------------------------------------------
# Test: Correct tagging
# --------------------------------------------------
run "correct_tags" {
  command = plan

  assert {
    condition     = aws_security_group.eks_cluster.tags["Type"] == "baseline"
    error_message = "Should have Type=baseline tag"
  }

  assert {
    condition     = aws_security_group.eks_cluster.tags["Profile"] == "eks-standard"
    error_message = "Should have Profile=eks-standard tag"
  }
}

# --------------------------------------------------
# Test: Workers have on-prem egress
# --------------------------------------------------
run "workers_onprem_egress" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.workers_to_onprem_443.from_port == 443
    error_message = "Workers should have egress 443 to on-prem"
  }
}

# --------------------------------------------------
# Test: Bidirectional kubelet
# --------------------------------------------------
run "bidirectional_kubelet" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.cluster_to_workers_10250.from_port == 10250
    error_message = "Cluster should egress 10250 to workers"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.workers_from_cluster_10250.from_port == 10250
    error_message = "Workers should accept 10250 from cluster"
  }
}

# --------------------------------------------------
# Test: mTLS only (15006 + 15012, no 15010)
# --------------------------------------------------
run "mtls_mesh_ports" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.istio_to_workers_15006.from_port == 15006
    error_message = "Istio should egress 15006 to workers"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.istio_to_workers_15012.from_port == 15012
    error_message = "Istio should egress 15012 (mTLS xDS) to workers"
  }
}
