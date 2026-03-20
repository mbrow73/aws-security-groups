# Google Cloud Armor; What It Is and How It Works

## The Baseline (Free, Automatic)

Every GCP project gets **standard network DDoS protection** out of the box for external passthrough NLBs, protocol forwarding, and VMs with public IPs. Always-on, no config needed. Covers basic volumetric attack mitigation at the network edge. Included with Cloud Armor Standard; no subscription required.

> [Standard vs Advanced Network DDoS Protection](https://cloud.google.com/armor/docs/advanced-network-ddos)

---

## Pricing Tiers

### Standard (Pay-as-you-go)

Per-policy and per-request pricing. You get:

- Security policies with custom rules (CEL expressions)
- Pre-configured WAF rules (OWASP Top 10)
- IP and geo-based filtering
- Rate limiting
- Standard network DDoS protection (always-on, included)

### Enterprise ($3,000/mo subscription)

Everything in Standard, plus:

- **Adaptive Protection**: ML-based anomaly detection that auto-generates WAF rules when it spots attack patterns
- **Threat Intelligence**: Named IP lists from Google's threat feeds
- **Advanced rate limiting** and bot management
- **DDoS bill protection**: If an attack spikes your infra costs, Google credits you back
- **DDoS response team**: Direct support from Google during active incidents
- **Advanced Network DDoS Protection**: Per-region targeted attack mitigation with traffic baselining

> [Cloud Armor Enterprise Overview](https://cloud.google.com/armor/docs/armor-enterprise-overview)  
> [Cloud Armor Pricing](https://cloud.google.com/armor/pricing)

---

## Security Policy Types

Three types. Each one attaches to different resources and supports different capabilities.

### Backend Security Policies (`CLOUD_ARMOR`)

Protect backend services behind proxy-based load balancers:

- Global external Application Load Balancer
- Classic Application Load Balancer
- Regional external Application Load Balancer
- Regional internal Application Load Balancer
- Global external proxy Network Load Balancer (TCP/SSL)
- Classic proxy Network Load Balancer (TCP/SSL)

Full L7 WAF; SQL injection, XSS, LFI, RCE, OWASP pre-configured rules, custom CEL rules, rate limiting, bot management, adaptive protection.

These attach to **backend services**. If your workload sits behind any of these proxy-based LB types, this is where you write your rules.

> [Backend Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#backend-security-policies)

### Edge Security Policies (`CLOUD_ARMOR_EDGE`)

Protect cached content. Supported on:

- Global external Application Load Balancer
- Classic Application Load Balancer

Deployed and enforced near the outermost perimeter of Google's network, upstream of where the Cloud CDN cache sits.

Key behaviors:

- Evaluated **before Identity-Aware Proxy (IAP)**. A request blocked by an edge policy is denied before IAP even attempts to authenticate the user.
- Can **coexist with backend security policies** on the same backend service. When both are attached, edge policies are evaluated first. Backend policies only see cache-miss requests that passed the edge policy.
- Only edge policies can be applied to **backend buckets**.

> [Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#edge-security-policies)

### Network Edge Security Policies (`CLOUD_ARMOR_NETWORK`)

Protect resources that don't sit behind a proxy-based load balancer:

- External passthrough Network Load Balancers
- Protocol forwarding
- VMs with public IP addresses

Enforced at the edge of Google's network, so traffic is blocked before it consumes VM or host resources. L3/L4 only; IP filtering, geo-blocking, byte offset filtering, rate limiting. No HTTP filtering, no WAF, no bot management (there's no proxy to inspect the traffic).

Network edge policies can be attached to **specific resources** (target pools, target instances, backend services, VM instances) for scoped filtering.

They can also be attached to a **network edge security service** (see Advanced DDoS below).

> [Network Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#network-edge-security-policies)

---

## Advanced Network DDoS Protection

Enterprise tier only.

This is where it can get confusing. Advanced DDoS protection uses the **same policy type** (`CLOUD_ARMOR_NETWORK`) as network edge security policies, but it's attached differently and serves a different purpose.

### How to configure it

```
1. Create a CLOUD_ARMOR_NETWORK security policy in a region
   $ gcloud compute security-policies create my-policy \
       --type CLOUD_ARMOR_NETWORK --region us-east1

2. Enable advanced DDoS on that policy
   $ gcloud compute security-policies update my-policy \
       --network-ddos-protection ADVANCED --region us-east1

3. Create a network edge security service and attach the policy
   $ gcloud compute network-edge-security-services create my-service \
       --security-policy my-policy --region us-east1
```

Once attached to the network edge security service, advanced DDoS protection **blankets ALL passthrough resources in that region** (external passthrough NLBs, protocol forwarding, VMs with public IPs). You don't attach it per-resource; the regional service covers everything.

### How it differs from network edge policy rules

Same policy type, two independent capabilities:

| | Network Edge Policy Rules | Advanced DDoS Protection |
|---|---|---|
| What it does | Your filtering rules (IP block, geo, rate limit) | Google's automated attack detection and mitigation |
| Who defines it | You write the rules | Google runs it automatically |
| Attachment | Specific resources OR network edge security service | Network edge security service only |
| Scope | Per-resource (when attached to resources) | Per-region blanket (when attached to service) |
| Tier required | Standard or Enterprise | Enterprise only |

You can use both independently or together. A single `CLOUD_ARMOR_NETWORK` policy can have your filtering rules AND have advanced DDoS enabled. Or you can have one without the other.

### Traffic baselining

When you first enable advanced DDoS, there's a 24-hour training period where Cloud Armor builds a baseline of your normal traffic patterns. After training, it applies additional mitigation techniques based on that historical data. This is what separates it from the free standard DDoS protection; it learns what normal looks like for your specific workloads and detects deviations.

### Standard vs Advanced DDoS comparison

| Feature | Standard (free) | Advanced (Enterprise) |
|---------|----------|----------|
| Protected endpoints | Passthrough NLB, protocol forwarding, public IP VMs | Same |
| Always-on monitoring | Yes | Yes |
| Forwarding rule enforcement | | Yes |
| Targeted attack mitigations | | Yes |
| Mitigation telemetry | | Yes |

> [Configure Advanced Network DDoS Protection](https://cloud.google.com/armor/docs/advanced-network-ddos)

---

## How It All Fits Together

```
Standard network DDoS (free)       Always-on for passthrough resources
      |
Cloud Armor Standard               You create security policies and write rules
      |
Cloud Armor Enterprise             ML, threat intel, adaptive protection, advanced DDoS
      |
      |-- Backend policies             L7 WAF; proxy-based LBs
      |       attached to: backend services
      |
      |-- Edge policies                CDN filtering; evaluated before IAP
      |       attached to: backend services / backend buckets
      |       stacks with backend policies (evaluated first)
      |
      |-- Network edge policies        L3/L4 filtering; passthrough resources
      |       attached to: specific resources (target pool, VM, etc)
      |
      |-- Advanced DDoS                Regional blanket; auto-mitigation
              attached to: network edge security service (per-region)
              uses same CLOUD_ARMOR_NETWORK policy type as network edge policies
```

The tiers control what features you can use. The policy types control where you attach protection. Edge policies stack with backend policies. Network edge policies and advanced DDoS share the same policy type but differ in attachment and scope.

---

## References

- [Cloud Armor Product Overview](https://cloud.google.com/armor/docs/cloud-armor-overview)
- [Security Policy Overview](https://cloud.google.com/armor/docs/security-policy-overview)
- [Backend Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#backend-security-policies)
- [Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#edge-security-policies)
- [Network Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#network-edge-security-policies)
- [Advanced Network DDoS Protection](https://cloud.google.com/armor/docs/advanced-network-ddos)
- [Cloud Armor Enterprise Overview](https://cloud.google.com/armor/docs/armor-enterprise-overview)
- [Cloud Armor Pricing](https://cloud.google.com/armor/pricing)
- [Preconfigured WAF Rules](https://cloud.google.com/armor/docs/waf-rules)
- [Configure Security Policies](https://cloud.google.com/armor/docs/configure-security-policies)
