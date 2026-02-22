# Baseline Security Group Profiles

## eks-standard (Intranet Only)

> 5 security groups, 38 rules. Zero `0.0.0.0/0`. All cross-SG traffic uses security group references.

### Security Groups

| Security Group | Description |
|---|---|
| `baseline-vpc-endpoints` | VPC interface endpoints — ingress from local VPC only |
| `baseline-eks-cluster` | EKS control plane — API server + kubelet/webhook egress |
| `baseline-eks-workers` | Worker nodes — zero-trust intra-cluster mesh |
| `baseline-istio-nodes` | Istio intranet gateways — NLB ingress + mesh egress |
| `baseline-intranet-nlb` | Intranet NLB — corporate/on-prem ingress |

### Rules

#### baseline-vpc-endpoints

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | VPC CIDR | HTTPS to interface endpoints |
| ingress | 80 | tcp | VPC CIDR | HTTP for S3 gateway endpoint |

#### baseline-eks-cluster

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | → `eks-workers` SG | Kubernetes API from workers |
| ingress | 443 | tcp | → `istio-nodes` SG | Kubernetes API from istio |
| ingress | 443 | tcp | → `corporate-networks` PL | kubectl from corporate |
| egress | 443 | tcp | → `eks-workers` SG | Admission webhooks |
| egress | 10250 | tcp | → `eks-workers` SG | Kubelet (logs, exec, metrics) |
| egress | 10250 | tcp | → `istio-nodes` SG | Kubelet on istio nodes |
| egress | 15017 | tcp | → `eks-workers` SG | Istiod sidecar injection webhook |

#### baseline-eks-workers

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `eks-cluster` SG | Admission webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| ingress | 15017 | tcp | ← `eks-cluster` SG | Istiod sidecar injection |
| ingress | 15006 | tcp | ← `istio-nodes` SG | Mesh traffic from gateway |
| ingress | 15012 | tcp | ← `istio-nodes` SG | xDS config stream (mTLS) |
| ingress | 15006 | tcp | ← self | Envoy sidecar inbound (service-to-service) |
| ingress | 10250 | tcp | ← self | Istiod pod to local kubelet |
| ingress | 53 | tcp | ← self | CoreDNS (TCP) |
| ingress | 53 | udp | ← self | CoreDNS (UDP) |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 443 | tcp | → `corporate-networks` PL | On-prem addons via TGW |
| egress | 15006 | tcp | → self | Envoy sidecar outbound |
| egress | 53 | tcp | → self | CoreDNS (TCP) |
| egress | 53 | udp | → self | CoreDNS (UDP) |

#### baseline-istio-nodes

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 8443 | tcp | ← `intranet-nlb` SG | HTTPS from NLB |
| ingress | 8080 | tcp | ← `intranet-nlb` SG | HTTP from NLB |
| ingress | 15021 | tcp | ← `intranet-nlb` SG | Health check from NLB |
| ingress | 443 | tcp | ← `eks-cluster` SG | Webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| ingress | 15021 | tcp | ← self | Kubelet readiness probes |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 15006 | tcp | → `eks-workers` SG | Mesh traffic to pod sidecars |
| egress | 15012 | tcp | → `eks-workers` SG | istiod xDS (mTLS) |
| egress | 53 | tcp | → `eks-workers` SG | DNS (TCP) |
| egress | 53 | udp | → `eks-workers` SG | DNS (UDP) |

#### baseline-intranet-nlb

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `corporate-networks` PL | HTTPS from corporate |
| ingress | 80 | tcp | ← `corporate-networks` PL | HTTP from corporate |

---

## eks-internet (Internet + Intranet)

> 7 security groups, ~58 rules. Zero `0.0.0.0/0`. Client IP preservation ON — istio sees WAF NAT IPs, not NLB IPs.
>
> **Traffic flow:** WAF NAT IPs → IGW → GWLBe (transparent) → Internet NLB → Istio inet → Workers
>
> **Mutually exclusive** with eks-standard. Pick one per account.

### Security Groups

| Security Group | Description |
|---|---|
| `baseline-vpc-endpoints` | VPC interface endpoints — ingress from local VPC only |
| `baseline-eks-cluster` | EKS control plane — shared, serves both istio paths |
| `baseline-eks-workers` | Worker nodes — shared, ingress from both istio SGs |
| `baseline-istio-intranet-nodes` | Istio intranet gateways — corporate/on-prem traffic |
| `baseline-intranet-nlb` | Intranet NLB — corporate prefix list ingress |
| `baseline-istio-inet-nodes` | Istio internet gateways — WAF/internet traffic |
| `baseline-internet-nlb` | Internet NLB — WAF NAT IP ingress (client IP preserved) |

### Rules

#### baseline-vpc-endpoints

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | VPC CIDR | HTTPS to interface endpoints |
| ingress | 80 | tcp | VPC CIDR | HTTP for S3 gateway endpoint |

#### baseline-eks-cluster

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `eks-workers` SG | Kubernetes API from workers |
| ingress | 443 | tcp | ← `istio-intranet-nodes` SG | Kubernetes API from intranet istio |
| ingress | 443 | tcp | ← `istio-inet-nodes` SG | Kubernetes API from internet istio |
| ingress | 443 | tcp | ← `corporate-networks` PL | kubectl from corporate |
| egress | 443 | tcp | → `eks-workers` SG | Admission webhooks |
| egress | 10250 | tcp | → `eks-workers` SG | Kubelet on workers |
| egress | 10250 | tcp | → `istio-intranet-nodes` SG | Kubelet on intranet istio |
| egress | 10250 | tcp | → `istio-inet-nodes` SG | Kubelet on internet istio |
| egress | 15017 | tcp | → `eks-workers` SG | Istiod sidecar injection |

#### baseline-eks-workers

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `eks-cluster` SG | Admission webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| ingress | 15017 | tcp | ← `eks-cluster` SG | Istiod sidecar injection |
| ingress | 15006 | tcp | ← `istio-intranet-nodes` SG | Mesh from intranet gateway |
| ingress | 15012 | tcp | ← `istio-intranet-nodes` SG | xDS from intranet gateway |
| ingress | 15006 | tcp | ← `istio-inet-nodes` SG | Mesh from internet gateway |
| ingress | 15012 | tcp | ← `istio-inet-nodes` SG | xDS from internet gateway |
| ingress | 15006 | tcp | ← self | Envoy sidecar inbound |
| ingress | 10250 | tcp | ← self | Istiod to local kubelet |
| ingress | 53 | tcp | ← self | CoreDNS (TCP) |
| ingress | 53 | udp | ← self | CoreDNS (UDP) |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 443 | tcp | → `corporate-networks` PL | On-prem addons via TGW |
| egress | 15006 | tcp | → self | Envoy sidecar outbound |
| egress | 53 | tcp | → self | CoreDNS (TCP) |
| egress | 53 | udp | → self | CoreDNS (UDP) |

#### baseline-istio-intranet-nodes

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 8443 | tcp | ← `intranet-nlb` SG | HTTPS from NLB |
| ingress | 8080 | tcp | ← `intranet-nlb` SG | HTTP from NLB |
| ingress | 15021 | tcp | ← `intranet-nlb` SG | Health check from NLB |
| ingress | 443 | tcp | ← `eks-cluster` SG | Webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| ingress | 15021 | tcp | ← self | Kubelet readiness probes |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 15006 | tcp | → `eks-workers` SG | Mesh to pod sidecars |
| egress | 15012 | tcp | → `eks-workers` SG | istiod xDS (mTLS) |
| egress | 53 | tcp | → `eks-workers` SG | DNS (TCP) |
| egress | 53 | udp | → `eks-workers` SG | DNS (UDP) |

#### baseline-intranet-nlb

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `corporate-networks` PL | HTTPS from corporate |
| ingress | 80 | tcp | ← `corporate-networks` PL | HTTP from corporate |

#### baseline-istio-inet-nodes

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 8443 | tcp | ← `waf-nat-ips` PL | HTTPS from WAF (client IP preserved) |
| ingress | 8080 | tcp | ← `waf-nat-ips` PL | HTTP from WAF (client IP preserved) |
| ingress | 15021 | tcp | ← `waf-nat-ips` PL | Health check from NLB (WAF source) |
| ingress | 443 | tcp | ← `eks-cluster` SG | Webhook callbacks |
| ingress | 10250 | tcp | ← `eks-cluster` SG | Control plane to kubelet |
| ingress | 15021 | tcp | ← self | Kubelet readiness probes |
| egress | 443 | tcp | → `eks-cluster` SG | Kubernetes API |
| egress | 443 | tcp | → `vpc-endpoints` SG | ECR, S3, STS, CloudWatch |
| egress | 15006 | tcp | → `eks-workers` SG | Mesh to pod sidecars |
| egress | 15012 | tcp | → `eks-workers` SG | istiod xDS (mTLS) |
| egress | 53 | tcp | → `eks-workers` SG | DNS (TCP) |
| egress | 53 | udp | → `eks-workers` SG | DNS (UDP) |

#### baseline-internet-nlb

| Direction | Port | Protocol | Source / Destination | Description |
|---|---|---|---|---|
| ingress | 443 | tcp | ← `waf-nat-ips` PL | HTTPS from WAF NAT IPs |
| ingress | 80 | tcp | ← `waf-nat-ips` PL | HTTP from WAF NAT IPs |
