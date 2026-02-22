# AWS Security Group Platform

Self-service security group management across AWS accounts via GitOps. Teams write YAML, Terraform deploys.

## How It Works

```
Team YAML → GitHub PR → Validation (Actions) → Terraform Cloud → AWS Security Groups
```

1. **Teams** edit `accounts/<account-id>/security-groups.yaml`
2. **GitHub Actions** validates schema, guardrails, naming on PR
3. **Terraform Cloud** runs speculative plan on PR, applies on merge
4. **Baselines** deploy zero-trust EKS security groups with SG chaining

## Quick Start

```bash
# 1. Copy the example
cp -r accounts/_example accounts/<your-account-id>

# 2. Edit your config
vim accounts/<your-account-id>/security-groups.yaml

# 3. Open a PR
git checkout -b team/my-sg-request
git add accounts/<your-account-id>/
git commit -m "feat: security group request for <team>"
git push origin team/my-sg-request
```

## Repository Structure

```
├── accounts/
│   ├── _example/              # Template — copy this
│   └── <account-id>/          # One dir per AWS account
│       └── security-groups.yaml
├── baseline/
│   ├── main.tf                # Orchestrator — conditional profile deployment
│   ├── profiles/
│   │   ├── eks-standard/      # Intranet-only EKS (4 SGs)
│   │   ├── eks-internet/      # Internet + intranet EKS (6 SGs)
│   │   └── vpc-endpoints/     # VPC endpoint access (1 SG)
│   ├── prefix-lists.tf        # Managed prefix lists
│   └── tests/                 # Orchestrator-level terraform tests
├── modules/
│   ├── security-group/        # Generic SG from YAML
│   ├── account/               # Per-account wrapper
│   └── vpc-discovery/         # Auto-discover VPC
├── scripts/
│   └── validate.py            # Schema + guardrail validation
├── tests/
│   └── test_validate.py       # Pytest suite (25 cases)
├── guardrails.yaml            # Blocked ports, CIDR limits
└── prefix-lists.yaml          # Org-wide prefix list definitions
```

## Baseline Profiles

Pre-built zero-trust security group sets. Teams opt in via `baseline_profiles` in their YAML.

| Profile | SGs | Description |
|---|---|---|
| `eks-standard` | 4 + vpc-endpoints | Intranet-only EKS with SG chaining |
| `eks-internet` | 6 + vpc-endpoints | Internet + intranet EKS, WAF NAT IP ingress |
| `vpc-endpoints` | 1 | VPC interface endpoint access |

- `eks-standard` and `eks-internet` are **mutually exclusive**
- Both auto-deploy `vpc-endpoints` as a dependency
- All cross-SG rules use security group references — zero `0.0.0.0/0`
- Full rule tables: [`baseline/profiles/BASELINE-PROFILES.md`](baseline/profiles/BASELINE-PROFILES.md)

## Validation

PR validation catches:
- Schema errors (unknown keys, wrong types, typos)
- Guardrail violations (blocked ports, overly permissive CIDRs)
- Naming convention enforcement
- Duplicate rule detection
- Tag compliance
- Baseline profile conflicts

```bash
# Run locally
python scripts/validate.py accounts/<account-id>/security-groups.yaml

# Run tests
pytest tests/test_validate.py -v
```

## Docs

- [Team Guide](docs/team-guide.md) — How to request security groups
- [Naming Conventions](docs/naming-conventions.md) — Standards and patterns
- [TFC Setup](docs/tfc-setup.md) — Terraform Cloud workspace configuration
