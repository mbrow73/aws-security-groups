# AWS Security Group Platform

Self-service security group management across AWS accounts via GitOps. Teams write YAML, Terraform deploys.

## How It Works

```
Team YAML → GitHub PR → Validation (Actions) → Terraform Enterprise → AWS Security Groups
```

1. **Teams** edit `accounts/<account-id>/security-groups.yaml` and, when needed, set `accounts/<account-id>/tenant.yaml`
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

# 2a. Optional, set tenant slug (derived owner mapping comes from owners.yaml)
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
│       └── tenant.yaml        # Optional compatibility bridge, tenant slug only
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

## Tenant Compatibility Mode

The platform now supports a backward-compatible tenant registry path for future multi-tenant evolution without breaking existing single-tenant accounts.

- `owners.yaml` defines approved tenant slugs and their owner mappings.
- `accounts/<account-id>/tenant.yaml` is optional and contains only the tenant slug.
- `owner_team` can be derived from the tenant registry instead of being typed into each account YAML.

Current compatibility mode keeps the live account config shape stable:

```yaml
# accounts/<account-id>/tenant.yaml
tenant: default
```

Future tenant split layout is not yet active. The current supported account config remains:

```yaml
# accounts/<account-id>/security-groups.yaml
account_id: "123456789012"
environment: "prod"
carid: "600001725"
security_groups: {}
```
