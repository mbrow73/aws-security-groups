# Platform Security Groups

Platform security groups are built-in SGs that the platform owns and can create automatically for each account/region.

They are intentionally referenced like normal security groups in requestor YAML. Requestors should not need to learn a separate platform-reference field for these cases.

## Registry

Platform-owned built-ins are cataloged in:

```text
registry/platform-security-groups.yaml
```

Initial entry:

```yaml
platform_security_groups:
  vpc-endpoints:
    description: "Platform-managed security group for interface VPC endpoint access."
    owner_authority: "platform-sg"
    provision: "automatic"
    source: "vpc_cidr"
    regions: "account_regions"
    requestor_reference: true
    review_class: "platform_builtin"
```

## `vpc-endpoints`

`vpc-endpoints` represents the account/region security group used by interface VPC endpoints.

Target behavior:

- platform creates it automatically when a new account/region is onboarded
- ingress is populated from the discovered account/region VPC CIDR
- ownership and review route to the platform SG authority
- teams may reference it with normal SG reference syntax

Example requestor rule:

```yaml
egress:
  - protocol: "tcp"
    from_port: 443
    to_port: 443
    security_groups:
      - "vpc-endpoints"
    description: "HTTPS to interface VPC endpoints"
```

## Policy intent

Reference classification should treat platform security groups separately from tenant-owned SGs:

- platform built-in SG reference -> platform SG authority
- same-tenant SG reference -> tenant owner owns/reviews
- cross-tenant SG reference -> referenced SG owner is mandatory reviewer
- unknown SG reference -> validation error

## VPC CIDR discovery

For `source: "vpc_cidr"`, Terraform discovers the target VPC in the account/region and creates ingress from that VPC's CIDR block.

This avoids broad default ingress such as `10.0.0.0/8` or `100.64.0.0/10` and avoids making requestors manually provide VPC CIDRs.

If VPC discovery is ambiguous or fails, the Terraform run should fail instead of creating a broad fallback rule.

## Non-goals

This registry does not make requestors specify platform SG rules. Platform built-ins are still platform-owned and created from the registry.
