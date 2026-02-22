# AWS Security Group Platform - EKS Internet Profile
#
# Internet-facing EKS clusters with both intranet and internet paths.
# Zero-trust SG chaining with client IP preservation on NLBs.
#
# 6 security groups:
#   1. baseline-eks-cluster          (control plane ENIs)
#   2. baseline-eks-workers          (worker nodes — serves both istio paths)
#   3. baseline-istio-intranet-nodes (intranet istio gateways)
#   4. baseline-intranet-nlb         (corporate/on-prem NLB)
#   5. baseline-istio-inet-nodes     (internet istio gateways)
#   6. baseline-internet-nlb         (internet-facing NLB)
#
# Traffic flows:
#   Internet: WAF NAT IPs → IGW → GWLBe → Internet NLB → Istio inet nodes → Workers
#   Intranet: Corporate PL → Intranet NLB → Istio intranet nodes → Workers
#   On-prem:  Inet cluster → GWLBe core → TGW → on-prem (routed, no SG needed)
#
# NLBs are transparent (client IP preservation ON). Source IPs are preserved
# through the entire chain, so istio SGs accept from the original source
# (WAF prefix list or corporate prefix list), not the NLB IPs.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -------------------------------------------------------
# Data Sources
# -------------------------------------------------------

data "aws_ec2_managed_prefix_list" "corporate_networks" {
  name = "corporate-networks"
}

data "aws_ec2_managed_prefix_list" "waf_nat_ips" {
  name = "waf-nat-ips"
}

# -------------------------------------------------------
# Security Group Shells (no inline rules — avoids cycles)
# -------------------------------------------------------

resource "aws_security_group" "eks_cluster" {
  name_prefix = "baseline-eks-cluster-"
  description = "EKS control plane — API server + kubelet/webhook egress"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-eks-cluster"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "eks_workers" {
  name_prefix = "baseline-eks-workers-"
  description = "EKS worker nodes — serves both intranet and internet istio paths"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-eks-workers"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "istio_intranet_nodes" {
  name_prefix = "baseline-istio-intranet-"
  description = "Istio intranet gateways — corporate/on-prem traffic"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-istio-intranet-nodes"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "intranet_nlb" {
  name_prefix = "baseline-intranet-nlb-"
  description = "Intranet NLB — corporate/on-prem ingress"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-intranet-nlb"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "istio_inet_nodes" {
  name_prefix = "baseline-istio-inet-"
  description = "Istio internet gateways — WAF/internet traffic"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-istio-inet-nodes"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

resource "aws_security_group" "internet_nlb" {
  name_prefix = "baseline-internet-nlb-"
  description = "Internet NLB — WAF NAT IP ingress (client IP preserved)"
  vpc_id      = var.vpc_id

  tags = merge(var.common_tags, {
    Name    = "baseline-internet-nlb"
    Type    = "baseline"
    Profile = "eks-internet"
  })
}

# =======================================================
# CLUSTER — Control Plane ENIs
# =======================================================

# --- Ingress ---

resource "aws_vpc_security_group_ingress_rule" "cluster_from_workers_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API from worker nodes"
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_istio_intranet_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API from intranet istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_istio_inet_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API from internet istio nodes"
}

resource "aws_vpc_security_group_ingress_rule" "cluster_from_corporate_443" {
  security_group_id = aws_security_group.eks_cluster.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.corporate_networks.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Kubernetes API from corporate networks (kubectl)"
}

# --- Egress ---

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on worker nodes"
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_istio_intranet_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on intranet istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_istio_inet_10250" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Kubelet on internet istio nodes"
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_443" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Admission webhooks on worker nodes"
}

resource "aws_vpc_security_group_egress_rule" "cluster_to_workers_15017" {
  security_group_id            = aws_security_group.eks_cluster.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15017
  to_port                      = 15017
  ip_protocol                  = "tcp"
  description                  = "Istiod sidecar injection webhook"
}

# =======================================================
# WORKERS — Shared Worker Nodes (serves both istio paths)
# =======================================================

# --- Ingress ---

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_10250" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet"
}

resource "aws_vpc_security_group_ingress_rule" "workers_self_10250" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Istiod pod to local kubelet"
}

resource "aws_vpc_security_group_ingress_rule" "workers_self_dns_tcp" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "CoreDNS (TCP)"
}

resource "aws_vpc_security_group_ingress_rule" "workers_self_dns_udp" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "CoreDNS (UDP)"
}

resource "aws_vpc_security_group_ingress_rule" "workers_self_15006" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15006
  to_port                      = 15006
  ip_protocol                  = "tcp"
  description                  = "Envoy sidecar inbound capture (service-to-service)"
}

# Intranet istio → workers
resource "aws_vpc_security_group_ingress_rule" "workers_from_istio_intranet_15006" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 15006
  to_port                      = 15006
  ip_protocol                  = "tcp"
  description                  = "Intranet istio gateway mesh traffic to app pods"
}

# Internet istio → workers
resource "aws_vpc_security_group_ingress_rule" "workers_from_istio_inet_15006" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 15006
  to_port                      = 15006
  ip_protocol                  = "tcp"
  description                  = "Internet istio gateway mesh traffic to app pods"
}

# Intranet istio → istiod
resource "aws_vpc_security_group_ingress_rule" "workers_from_istio_intranet_15012" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 15012
  to_port                      = 15012
  ip_protocol                  = "tcp"
  description                  = "Intranet istio gateway to istiod xDS (mTLS)"
}

# Internet istio → istiod
resource "aws_vpc_security_group_ingress_rule" "workers_from_istio_inet_15012" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 15012
  to_port                      = 15012
  ip_protocol                  = "tcp"
  description                  = "Internet istio gateway to istiod xDS (mTLS)"
}

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_15017" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 15017
  to_port                      = 15017
  ip_protocol                  = "tcp"
  description                  = "Istiod sidecar injection webhook from control plane"
}

resource "aws_vpc_security_group_ingress_rule" "workers_from_cluster_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Admission webhook callbacks from control plane"
}

# --- Egress ---

resource "aws_vpc_security_group_egress_rule" "workers_to_cluster_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
}

resource "aws_vpc_security_group_egress_rule" "workers_to_vpce_443" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints (ECR, S3, STS, CloudWatch)"
}

resource "aws_vpc_security_group_egress_rule" "workers_self_dns_tcp" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "CoreDNS (TCP)"
}

resource "aws_vpc_security_group_egress_rule" "workers_self_dns_udp" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "CoreDNS (UDP)"
}

resource "aws_vpc_security_group_egress_rule" "workers_self_15006" {
  security_group_id            = aws_security_group.eks_workers.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15006
  to_port                      = 15006
  ip_protocol                  = "tcp"
  description                  = "Envoy sidecar outbound to other pod sidecars"
}

# Workers → on-prem addons via TGW
resource "aws_vpc_security_group_egress_rule" "workers_to_onprem_443" {
  security_group_id = aws_security_group.eks_workers.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.corporate_networks.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS to on-prem services (addons, config) via TGW"
}

# =======================================================
# ISTIO INTRANET NODES — Corporate/On-Prem Path
# =======================================================

# --- Ingress (from intranet NLB — client IP preserved = corporate PL) ---

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_nlb_8080" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "HTTP from intranet NLB"
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_nlb_8443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "HTTPS from intranet NLB"
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_nlb_15021" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.intranet_nlb.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Istio health check from NLB"
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_self_15021" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.istio_intranet_nodes.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Kubelet readiness probes"
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_cluster_10250" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet"
}

resource "aws_vpc_security_group_ingress_rule" "istio_intranet_from_cluster_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Webhook callbacks from control plane"
}

# --- Egress ---

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_cluster_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_vpce_443" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints"
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_workers_15012" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15012
  to_port                      = 15012
  ip_protocol                  = "tcp"
  description                  = "istiod xDS config stream (mTLS)"
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_workers_15006" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15006
  to_port                      = 15006
  ip_protocol                  = "tcp"
  description                  = "Mesh traffic to app pod sidecars"
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_workers_dns_tcp" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "DNS resolution (TCP)"
}

resource "aws_vpc_security_group_egress_rule" "istio_intranet_to_workers_dns_udp" {
  security_group_id            = aws_security_group.istio_intranet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "DNS resolution (UDP)"
}

# =======================================================
# INTRANET NLB — Corporate/On-Prem
# TODO: Max to fill in additional rules
# =======================================================

resource "aws_vpc_security_group_ingress_rule" "intranet_nlb_from_corporate_443" {
  security_group_id = aws_security_group.intranet_nlb.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.corporate_networks.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from corporate networks"
}

resource "aws_vpc_security_group_ingress_rule" "intranet_nlb_from_corporate_80" {
  security_group_id = aws_security_group.intranet_nlb.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.corporate_networks.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP from corporate networks"
}

# =======================================================
# ISTIO INTERNET NODES — WAF/Internet Path
# Client IP preserved through NLB — source is WAF NAT IPs
# =======================================================

# --- Ingress (source = WAF NAT IPs, preserved through transparent NLB) ---

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_waf_8080" {
  security_group_id = aws_security_group.istio_inet_nodes.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.waf_nat_ips.id
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
  description       = "HTTP from WAF (client IP preserved through NLB)"
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_waf_8443" {
  security_group_id = aws_security_group.istio_inet_nodes.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.waf_nat_ips.id
  from_port         = 8443
  to_port           = 8443
  ip_protocol       = "tcp"
  description       = "HTTPS from WAF (client IP preserved through NLB)"
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_waf_15021" {
  security_group_id = aws_security_group.istio_inet_nodes.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.waf_nat_ips.id
  from_port         = 15021
  to_port           = 15021
  ip_protocol       = "tcp"
  description       = "Istio health check from NLB (WAF source)"
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_self_15021" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.istio_inet_nodes.id
  from_port                    = 15021
  to_port                      = 15021
  ip_protocol                  = "tcp"
  description                  = "Kubelet readiness probes"
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_cluster_10250" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 10250
  to_port                      = 10250
  ip_protocol                  = "tcp"
  description                  = "Control plane to kubelet"
}

resource "aws_vpc_security_group_ingress_rule" "istio_inet_from_cluster_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Webhook callbacks from control plane"
}

# --- Egress ---

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_cluster_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_cluster.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Kubernetes API server"
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_vpce_443" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = var.vpc_endpoints_sg_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "VPC endpoints"
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_workers_15012" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15012
  to_port                      = 15012
  ip_protocol                  = "tcp"
  description                  = "istiod xDS config stream (mTLS)"
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_workers_15006" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 15006
  to_port                      = 15006
  ip_protocol                  = "tcp"
  description                  = "Mesh traffic to app pod sidecars"
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_workers_dns_tcp" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "tcp"
  description                  = "DNS resolution (TCP)"
}

resource "aws_vpc_security_group_egress_rule" "istio_inet_to_workers_dns_udp" {
  security_group_id            = aws_security_group.istio_inet_nodes.id
  referenced_security_group_id = aws_security_group.eks_workers.id
  from_port                    = 53
  to_port                      = 53
  ip_protocol                  = "udp"
  description                  = "DNS resolution (UDP)"
}

# =======================================================
# INTERNET NLB — WAF NAT IP Ingress
# NLB is transparent — this SG is for the NLB ENIs.
# Client IP preservation ON, so source = WAF NAT IPs.
# =======================================================

resource "aws_vpc_security_group_ingress_rule" "internet_nlb_from_waf_443" {
  security_group_id = aws_security_group.internet_nlb.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.waf_nat_ips.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from WAF NAT IPs"
}

resource "aws_vpc_security_group_ingress_rule" "internet_nlb_from_waf_80" {
  security_group_id = aws_security_group.internet_nlb.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.waf_nat_ips.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP from WAF NAT IPs"
}
