# Google Cloud Armor; What It Is and How It Works

## The Baseline (Free, Automatic)

Every GCP project gets volumetric DDoS protection out of the box. Google's edge network (Maglev/Andromeda) absorbs L3/L4 garbage before it reaches your infrastructure. You don't configure it, you don't pay for it; it's just there.

This is not "Cloud Armor" per se. It's infrastructure-level protection that exists whether you use Cloud Armor or not.

> [Cloud Armor Product Overview](https://cloud.google.com/armor/docs/cloud-armor-overview)

---

## Pricing Tiers

Cloud Armor has two tiers that determine what features you get access to.

### Standard (Pay-as-you-go)

Per-policy and per-request pricing. You get:

- WAF rules (pre-configured OWASP + custom CEL expressions)
- IP and geo-based filtering
- Rate limiting
- Manual rule management

Good enough for most workloads. You create security policies, attach them to your resources, and write rules.

### Enterprise ($3,000/mo subscription)

Everything in Standard, plus:

- **Adaptive Protection**: ML-based anomaly detection that auto-generates WAF rules when it spots attack patterns
- **Threat Intelligence**: Named IP lists from Google's threat feeds
- **Advanced rate limiting** and bot management
- **DDoS bill protection**: If an attack spikes your infra costs, Google credits you back
- **DDoS response team**: Direct support from Google during active incidents
- **Advanced Network DDoS Protection**: Per-region blanket protection (more on this below)

> [Cloud Armor Pricing](https://cloud.google.com/armor/pricing)

---

## Security Policy Types

This is where people get confused. There are three types of security policies, and each one attaches to different resources.

### Backend Security Policies

These attach to **backend services** behind external Application Load Balancers (HTTP/S).

This is what most people mean when they say "Cloud Armor." Full L7 WAF capability; SQL injection, XSS, LFI, RCE, OWASP pre-configured rules, custom rules using CEL expressions, rate limiting, bot detection.

If your workload sits behind a proxy-based (L7) load balancer, this is your tool.

> [Backend Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#backend-security-policies)

### Edge Security Policies

These attach to **backend buckets** (Cloud CDN).

Filtering happens at Google's CDN edge *before* the cache is even checked. If a request gets blocked, it never hits your origin and never serves cached content.

The scope here is narrow; this is specifically for protecting CDN-served content (static assets, media, etc). Same rule language as backend policies but scoped to CDN use cases like IP filtering, geo-blocking, and header-based rules.

> [Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#edge-security-policies)

### Network Edge Security Policies

These attach to **external passthrough Network Load Balancers**, protocol forwarding rules, and VMs with public IPs.

L3/L4 only; no deep packet inspection, no WAF rules. You get IP allowlists/denylists, geo-blocking, and byte offset filtering. Applied at Google's network edge before traffic reaches your VMs.

This exists because passthrough NLBs and public-IP VMs can't use backend security policies (those require a proxy LB). Network edge policies fill that gap. Without them, your only option was VPC firewall rules, which burn VM resources processing traffic that should've been dropped way earlier in the path.

> [Network Edge Security Policies](https://cloud.google.com/armor/docs/security-policy-overview#network-edge-security-policies)

---

## Advanced Network DDoS Protection

Enterprise tier only. You enable this per-region, and it blankets every external-facing resource in that region:

- External passthrough NLBs
- Protocol forwarding
- VMs with public IPs

Google builds traffic baselines for your resources, monitors for anomalies, and auto-mitigates volumetric attacks without you writing any rules.

This is above and beyond the free always-on DDoS protection. Think of it as upgrading from a basic bouncer to a private security team that learns your normal traffic patterns and responds to anything unusual.

> [Advanced Network DDoS Protection](https://cloud.google.com/armor/docs/advanced-network-ddos)

---

## How It All Fits Together

```
Always-on DDoS (free)          Baseline; everyone gets it
      |
Cloud Armor Standard           You start writing security policies
      |
Cloud Armor Enterprise         ML, threat intel, adaptive protection
      |
      |-- Backend policies         L7 WAF for proxy-based LBs
      |-- Edge policies            CDN content filtering
      |-- Network edge policies    L3/L4 for passthrough resources
      |-- Advanced DDoS            Per-region blanket protection
```

The tiers control *what features* you can use. The policy types control *where* you attach protection. They're two separate dimensions.

---

## References

- [Cloud Armor Product Overview](https://cloud.google.com/armor/docs/cloud-armor-overview)
- [Security Policy Overview](https://cloud.google.com/armor/docs/security-policy-overview)
- [Advanced Network DDoS Protection](https://cloud.google.com/armor/docs/advanced-network-ddos)
- [Cloud Armor Pricing](https://cloud.google.com/armor/pricing)
- [Preconfigured WAF Rules](https://cloud.google.com/armor/docs/waf-rules)
