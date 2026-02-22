# Full orchestrator test: eks-standard + vpc-endpoints (auto-dependency)
# Run from baseline/: terraform test
#
# Uses mock_provider — no AWS credentials needed.
# command = apply so SG IDs resolve (mock provider generates fake IDs).

mock_provider "aws" {}

variables {
  account_id        = "123456789012"
  vpc_id            = "vpc-0123456789abcdef0"
  baseline_profiles = ["eks-standard"]
  tags = {
    Environment = "test"
  }
}

override_data {
  target = data.aws_vpc.selected[0]
  values = {
    id         = "vpc-0123456789abcdef0"
    cidr_block = "10.0.0.0/16"
  }
}

# --------------------------------------------------
# Test: eks-standard auto-enables vpc-endpoints (5 SGs total)
# --------------------------------------------------
run "eks_standard_full_deployment" {
  command = apply

  # Profile deployment
  assert {
    condition     = length(module.vpc_endpoints) == 1
    error_message = "vpc-endpoints should auto-deploy with eks-standard"
  }

  assert {
    condition     = length(module.eks_standard) == 1
    error_message = "eks-standard module should be deployed"
  }

  assert {
    condition     = length(module.eks_internet) == 0
    error_message = "eks-internet should NOT be deployed"
  }

  # VPCE SG wired through
  assert {
    condition     = output.vpc_endpoints_security_group_id != null
    error_message = "vpc-endpoints SG should be output"
  }

  # EKS standard SGs
  assert {
    condition     = output.eks_cluster_security_group_id != null
    error_message = "EKS cluster SG should be output"
  }

  assert {
    condition     = output.eks_workers_security_group_id != null
    error_message = "EKS workers SG should be output"
  }

  assert {
    condition     = output.istio_nodes_security_group_id != null
    error_message = "Istio nodes SG should be output"
  }

  assert {
    condition     = output.intranet_nlb_security_group_id != null
    error_message = "Intranet NLB SG should be output"
  }

  # eks-internet should be null
  assert {
    condition     = output.inet_eks_cluster_security_group_id == null
    error_message = "eks-internet outputs should be null"
  }
}
