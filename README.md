# AWS Security Group Platform

Self-service security group management across AWS accounts via GitOps. Teams write YAML, Terraform deploys.

## How It Works

```
Team YAML → GitHub PR → Validation (Actions) → Terraform Enterprise → AWS Security Groups
```

1. **Teams** edit either `accounts/<account-id>/security-groups.yaml` or tenant-split files under `accounts/<account-id>/<tenant>/security-groups.yaml`
2. **GitHub Actions** validates schema, guardrails, naming on PR
3. **Terraform Enterprise** runs speculative plan on PR, applies on merge

> **Baseline SGs** (EKS zero-trust profiles) have moved to their own module:
> [`terraform-aws-eks-baseline-sgs`](https://github.com/mbrow73/terraform-aws-eks-baseline-sgs) — published on TFE private registry.

## Quick Start

```bash
# 1. Copy the example
cp -r accounts/_example accounts/<your-account-id>

# 2. Edit your config
vim accounts/<your-account-id>/security-groups.yaml

# Optional compatibility bridge for legacy single-tenant accounts
echo 'tenant: default' > accounts/<your-account-id>/tenant.yaml

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
│       ├── security-groups.yaml
│       ├── tenant.yaml        # Optional legacy bridge, tenant slug only
│       └── <tenant>/
│           └── security-groups.yaml
├── owners.yaml                # Tenant and owner registry
├── modules/
│   ├── security-group/        # Generic SG from YAML
│   └── account/               # Per-account wrapper (yamldecode → SGs)
├── scripts/
│   └── validate.py            # Schema + guardrail validation
├── tests/
│   └── test_validate.py       # Pytest suite (25 cases)
├── guardrails.yaml            # Blocked ports, CIDR limits
└── docs/
    ├── team-guide.md
    ├── operational-model.md
    ├── anti-patterns-and-mitigations.md
    ├── naming-conventions.md
    └── tfe-setup.md
```

## Validation

PR validation catches:
- Schema errors (unknown keys, wrong types, typos)
- Guardrail violations (blocked ports, overly permissive CIDRs)
- Naming convention enforcement
- Duplicate rule detection
- Tag compliance
- Unknown tenant / owner mappings
- Mixed legacy + tenant-split layout conflicts

```bash
# Run locally
python scripts/validate.py accounts/<account-id>

# Run tests
pytest tests/test_validate.py -v
```

## Docs

- [Team Guide](docs/team-guide.md) — How to request security groups
- [Operational Model](docs/operational-model.md) — Two-layer SG model, baselines vs team SGs
- [Anti-Patterns & Mitigations](docs/anti-patterns-and-mitigations.md) — Risks and layered defenses
- [Naming Conventions](docs/naming-conventions.md) — Standards and patterns
- [TFE Setup](docs/tfe-setup.md) — Terraform Enterprise workspace configuration

## Tenant Compatibility and Tenant-Split Layout

The platform supports both layouts, but an account must use exactly one at a time.

### Legacy single-file layout

```text
accounts/
  123456789012/
    security-groups.yaml
    tenant.yaml   # optional
```

### Tenant-split layout

```text
accounts/
  123456789012/
    payments/security-groups.yaml
    data-platform/security-groups.yaml
```

Rules:
- tenant slugs must exist in `owners.yaml`
- legacy and tenant-split files cannot coexist in the same account dir
- tenant files are merged into one normalized account config before Terraform runs
- future requester YAML can stay lean, with tenant identity driven by directory slug and registry metadata
