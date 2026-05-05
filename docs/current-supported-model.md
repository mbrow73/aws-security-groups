# Current Supported Model

This document defines what the AWS Security Group Platform supports today.

The intent is to keep the current production model explicit and stable before adding future ownership, tenant, or API-front-door capabilities.

## Current Contract

The platform currently supports a **single-tenant-per-account** operating model.

```text
accounts/
  <account-id>/
    security-groups.yaml
```

One AWS account maps to one account configuration file. That file is the source of truth for self-service security groups in that account.

## Account File Responsibilities

`accounts/<account-id>/security-groups.yaml` owns:

- AWS account ID
- environment
- CARID
- default region and/or account-level regions
- account-level generated corporate tagging inputs
- all self-service security groups for that account
- ingress and egress rules for those self-service security groups

## What Is Supported Today

Supported today:

- one account directory per AWS account
- one `security-groups.yaml` file per managed account
- PR-based change workflow
- GitHub Actions validation
- Terraform Enterprise deployment per changed account
- account-level `carid`
- account-level `environment`
- account-level `regions` with SG-level region overrides
- security group rules using CIDRs, prefix lists, self references, baseline references, or same-account SG references
- cross-account connectivity represented with CIDR or prefix-list based rules when needed

## What Is Not Supported Today

Not supported today:

- tenant subdirectories under an account
- multiple tenant-owned SG files in the same account
- tenant registry
- owner registry
- owner-based review enforcement
- cross-account security group references as the preferred model
- API/UI front door
- per-SG CARID as a validated ownership primitive

These may be future capabilities, but they are not part of the current operating contract.

## Single-Tenant Meaning

For the current model, “single tenant” means the account file should represent one accountable workload ownership boundary.

That boundary may be an application, platform workload, service family, or team-owned account, but it should not be used as an unmanaged dumping ground for unrelated teams.

If an account is shared by multiple unrelated teams or ownership domains, it should be treated as a future multi-tenant candidate and reviewed with the platform/security owners before onboarding at scale.

## Ownership Today

Today, ownership is implied by the account context, PR author/review path, CARID, and security group naming/tags. There is no first-class owner registry yet.

Until ownership metadata is added, reviewers should treat account onboarding and large rule changes as the control point for confirming who owns the account and workload.

## Guardrails

Current guardrails:

- keep requestor YAML simple
- do not add tenant layout before the platform explicitly enables it
- do not use cross-account SG references as the default pattern
- use CIDR or prefix-list based references for cross-account boundaries
- keep baseline SGs separate from team SGs
- keep Git/PR/Terraform as the execution backbone

## Future Direction

Future phases may add:

- optional ownership metadata
- lightweight owner registry
- owner-aware PR summary and review hints
- dormant tenant model design
- tenant split only behind feature flag and only for real multi-tenant accounts
- thin API/UI front door that creates PRs rather than bypassing Git/Terraform
