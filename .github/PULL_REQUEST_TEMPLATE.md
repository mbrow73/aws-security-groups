## Security Group Request

**Team:** <!-- Your team name -->
**Account ID:** <!-- 12-digit AWS account ID -->
**Requested by:** <!-- Your name and email -->

### Security Groups

| Name | Purpose |
|---|---|
| `sg-name-here` | Brief description |

### Why

<!-- What workload is this for? Why do you need these SGs? -->

### Checklist

- [ ] Account ID is correct (12 digits)
- [ ] Every rule has a description explaining *why*
- [ ] No 0.0.0.0/0 ingress
- [ ] Egress is scoped to what's actually needed
- [ ] Used prefix lists where applicable (WAF, corporate, VPC endpoints)
- [ ] Tagged with Team, Environment, and Application

### Additional Context

<!-- PCI scope? New service? Migration? Anything reviewers should know. -->
