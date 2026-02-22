# Full orchestrator test: eks-internet + vpc-endpoints (auto-dependency)
# Run from baseline/: terraform test

mock_provider "aws" {}

variables {
  account_id        = "123456789012"
  vpc_id            = "vpc-0123456789abcdef0"
  baseline_profiles = ["eks-internet"]
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
# Test: eks-internet auto-enables vpc-endpoints (7 SGs total)
# --------------------------------------------------
run "eks_internet_full_deployment" {
  command = apply

  # Profile deployment
  assert {
    condition     = length(module.vpc_endpoints) == 1
    error_message = "vpc-endpoints should auto-deploy with eks-internet"
  }

  assert {
    condition     = length(module.eks_internet) == 1
    error_message = "eks-internet module should be deployed"
  }

  assert {
    condition     = length(module.eks_standard) == 0
    error_message = "eks-standard should NOT be deployed"
  }

  # VPCE SG
  assert {
    condition     = output.vpc_endpoints_security_group_id != null
    error_message = "vpc-endpoints SG should be output"
  }

  # All 6 EKS internet SGs
  assert {
    condition     = output.inet_eks_cluster_security_group_id != null
    error_message = "EKS cluster SG should be output"
  }

  assert {
    condition     = output.inet_eks_workers_security_group_id != null
    error_message = "EKS workers SG should be output"
  }

  assert {
    condition     = output.inet_istio_intranet_nodes_security_group_id != null
    error_message = "Istio intranet nodes SG should be output"
  }

  assert {
    condition     = output.inet_intranet_nlb_security_group_id != null
    error_message = "Intranet NLB SG should be output"
  }

  assert {
    condition     = output.inet_istio_inet_nodes_security_group_id != null
    error_message = "Istio internet nodes SG should be output"
  }

  assert {
    condition     = output.inet_internet_nlb_security_group_id != null
    error_message = "Internet NLB SG should be output"
  }

  # eks-standard should be null
  assert {
    condition     = output.eks_cluster_security_group_id == null
    error_message = "eks-standard outputs should be null"
  }
}
