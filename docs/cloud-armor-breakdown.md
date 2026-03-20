# Google Cloud Armor; What It Is and How It Works

## The Baseline (Free, Automatic)

Every GCP project gets standard network DDoS protection out of the box for external passthrough NLBs, protocol forwarding, and VMs with public IPs. This is always-on, always free; you don't configure anything. It covers basic volumetric attack mitigation at the network edge.

This is covered under Cloud Armor Standard and doesn't require any subscriptions.

> [Standard vs Advanced Network DDoS Protection](https://cloud.google.com/armor/docs/advanced-network-ddos#compare)

---

## Pricing Tiers

Cloud Armor has two tiers that determine what features you get access to.

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
- **Advanced Network DDoS Protection**: Per-region targeted attack mitigation with traffic baselining (more on this below)

> [Cloud Armor Enterprise Overview](https://cloud.google.com/armor/docs/armor-enterprise-overview)  
> [Cloud Armor Pricing](https://cloud.google.com/armor/pricing)

---

## Security Policy Types

There are three types of service-level security policies. Each one attaches to different resources and supports different capabilities.

### Backend Security Policies

These protect backend services exposed by load balancers. Supported LB types:

- Global external Application Load Balancer
- Classic Application Load Balancer
- Regional external Application Load Balancer
- Regional internal Application Load Balancer
- Global external proxy Network Load Balancer (TCP/SSL)
- Classic proxy Network Load Balancer (TCP/SSL)

This is the full L7 WAF; SQL injection, XSS, LFI, RCE, OWASP pre-configured rules, custom rules using CEL, rate limiting, bot management, adaptive protection. If your workload sits behind any of these LB types, this is where you write your rules.

Backend security policies use the type flag `CLOUD_ARMOR`.

> [Backend Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#backend-security-policies)

### Edge Security Policies

These protect cached content and are supported on:

- Global external Application Load Balancer
- Classic Application Load Balancer

Edge policies are deployed and enforced near the outermost perimeter of Google's network, upstream of where the Cloud CDN cache sits. They're evaluated **before Identity-Aware Proxy (IAP)**; a request blocked by an edge policy is denied before IAP even attempts to authenticate the user.

Edge security policies can **coexist with backend security policies** on the same backend service. When both are attached, edge policies are evaluated first. Backend policies only see cache-miss requests that have already passed the edge policy.

They can be applied to backend services (regardless of backend type) and to backend buckets. Only edge policies can be applied to backend buckets.

Edge security policies use the type flag `CLOUD_ARMOR_EDGE`.

> [Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#edge-security-policies)

### Network Edge Security Policies

These protect resources that don't sit behind a proxy-based load balancer:

- External passthrough Network Load Balancers
- Protocol forwarding
- VMs with public IP addresses

Enforced at the edge of Google's network, so blocking happens before traffic consumes VM or host resources. This is critical for preventing high-volume attacks from exhausting resources on the target workload.

Network edge policies support IP filtering, geo-blocking, byte offset filtering, and rate limiting; but no HTTP filtering, no WAF rules, and no bot management. The scope is L3/L4.

Network edge security policies are tightly coupled with advanced network DDoS protection (see below); they share the same policy type (`CLOUD_ARMOR_NETWORK`) and the same attachment model via the network edge security service.

> [Network Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#network-edge-security-policies)

---

## Advanced Network DDoS Protection

Enterprise tier only. This is where network edge security policies and DDoS protection converge.

### How it works

You create a security policy of type `CLOUD_ARMOR_NETWORK` in a specific region, then enable `--network-ddos-protection ADVANCED` on that policy. You then attach it to a **network edge security service** in that region. Once attached, all applicable endpoints in that region (external passthrough NLBs, protocol forwarding, VMs with public IPs) get always-on targeted volumetric attack detection and mitigation.

### The relationship with network edge security policies

They're the same policy type. A `CLOUD_ARMOR_NETWORK` policy serves two purposes:

1. **Network edge security rules**: The filtering rules you write (IP allow/deny, geo-blocking, byte offset filtering)
2. **Advanced DDoS protection**: The `--network-ddos-protection ADVANCED` flag on the same policy enables targeted DDoS mitigation

Both are attached to the network edge security service. You're not managing two separate things; it's one policy type that handles both rule-based filtering and DDoS protection for the same set of resources.

### Traffic baselining

When you first enable advanced DDoS protection, there's a 24-hour training period where Cloud Armor builds a baseline of your normal traffic patterns. After training, it applies additional mitigation techniques based on that baseline. This is what makes it "advanced" compared to the standard always-on protection; it learns what normal looks like for your specific workloads.

### Standard vs Advanced

| Feature | Standard | Advanced |
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
Standard network DDoS (free)       Always-on baseline for passthrough resources
      |
Cloud Armor Standard               You start writing security policies
      |
Cloud Armor Enterprise             ML, threat intel, adaptive protection
      |
      |-- Backend policies             L7 WAF for proxy-based LBs
      |-- Edge policies                CDN filtering (evaluated before IAP; stacks with backend policies)
      |-- Network edge policies  }
      |                          }--   Same CLOUD_ARMOR_NETWORK policy type
      |-- Advanced DDoS          }     Attached via network edge security service
```

The tiers control *what features* you can use. The policy types control *where* you attach protection. Edge policies stack with backend policies on the same backend service. Network edge policies and advanced DDoS protection are two sides of the same coin.

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
