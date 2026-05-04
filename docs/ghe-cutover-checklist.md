# GitHub Enterprise Cutover Checklist

This runbook covers lift-and-shift of the SG framework from the personal GitHub repo into GitHub Enterprise.

The goal is to verify the V2 foundation in the real environment where GHE teams, branch protection, CloudIaC, TFE, and secrets exist.

## Preconditions

- Target repo exists in GitHub Enterprise.
- Repo has Actions enabled.
- Repo can reach CloudIaC / TFE endpoints from GHE runners.
- The platform review team exists:

```text
https://github.aexp.com/orgs/amex-eng/teams/nsae
```

- A classic PAT or approved equivalent exists for Review Gate team lookup.
- PAT owner can see `amex-eng/nsae` membership.
- PAT includes org-read capability, for example `read:org` for classic PATs.

## Required secrets

Add these before testing PRs.

### Review Gate

```text
REVIEW_GATE_PAT
```

Used by `.github/workflows/review-gate.yml` to resolve configured GHE team membership.

If missing, Review Gate should run but stay pending because authority membership resolves to empty.

Review Gate also attempts to create or update a PR comment marked with:

```text
<!-- sg-review-policy-bot -->
```

The workflow needs PR comment write permission in GHE. In GitHub Actions terms this is typically:

```yaml
permissions:
  issues: write
```

The comment is best-effort. If comment creation is blocked, Review Gate should log the failure and continue setting the commit status.

### CloudIaC / TFE

Use the existing secret names expected by `.github/workflows/tfe-provision.yml` and `scripts/tfe_workspace.py`.

Verify at least:

```text
CLDIAC_URL
CLDIAC_TOKEN
TFE_TOKEN
```

If actual enterprise secret names differ, update the workflow during cutover rather than aliasing silently.

### Slack

If Slack notifications are desired:

```text
SLACK_WEBHOOK_URL
```

If not configured, Slack notification behavior should be treated as non-blocking or disabled deliberately.

## Registry checks

Confirm these files exist and are correct:

```text
registry/tenants.yaml
registry/review-authorities.yaml
registry/platform-security-groups.yaml
```

Initial authority should include:

```yaml
authorities:
  platform-sg:
    ghe_host: "github.aexp.com"
    org: "amex-eng"
    team_slug: "nsae"
```

Default tenant should reference:

```yaml
review_authority: "platform-sg"
```

## Branch protection

Configure branch protection on `main`.

Recommended required checks:

- Validate Security Groups
- Post Validation Summary, optional but useful
- Post Change Summary, optional but useful
- Review Requirements / Review Gate status
- TFE Provision / Plan, once CloudIaC/TFE is wired

Recommended review settings:

- require pull request before merge
- require latest branch / up-to-date checks if enterprise policy supports it
- require conversation resolution
- do not rely only on CODEOWNERS for authorization

CODEOWNERS is still useful UX, but Review Gate is the deterministic authority enforcement layer.

## First validation PR

Create a disposable PR similar to the personal-repo test PR.

Test account shape:

```text
accounts/<fake-or-safe-account>/payments-preview/security-groups.yaml
accounts/<fake-or-safe-account>/data-preview/security-groups.yaml
```

Test cases:

1. Tenant-layout account validates.
2. PR summary shows involved tenants, not only `default`.
3. SG can reference platform built-in:

```yaml
security_groups:
  - "vpc-endpoints"
```

4. Cross-tenant SG reference with matching `reference_grants` skips extra target approval.
5. Cross-tenant SG reference without a grant requires target tenant authority approval.
6. Unknown SG reference fails validation.
7. Review Gate posts a `Review Policy Summary` comment.

## Expected Review Gate behavior

Without approvals:

```text
Review Gate pending: 0/N <org>/<team>
```

With one nonprod tenant approval from the correct authority:

```text
1/1 <org>/<team>
```

With prod/framework changes:

```text
2/2 <org>/<team>
```

For cross-tenant refs:

- matching reference grant: no extra target authority approval
- no matching grant: 1 approval from referenced/target tenant authority

For `vpc-endpoints` references:

- no extra reviewer beyond the source change's normal policy

Review Gate should also post or update a PR comment named:

```text
🛡️ Review Policy Summary
```

Expected comment content:

- required authorities and approval counts
- changed account / tenant context
- classified SG references
- raw policy JSON in collapsible details

## Expected TFE behavior

For legacy layout:

```text
accounts/<account-id>/security-groups.yaml
```

For tenant layout:

```text
accounts/<account-id>/<tenant>/security-groups.yaml
```

The upload path should stage normalized YAML so Terraform still reads:

```text
accounts/<account-id>/security-groups.yaml
```

The TFE workspace should not need to understand tenant folders.

## VPC discovery expectations

Platform built-in `vpc-endpoints` is created from discovered VPC CIDR.

Current assumption:

- one available VPC per account/region

If multiple VPCs exist in an account/region, Terraform discovery should fail rather than pick a VPC silently.

Multi-VPC support requires a future explicit selector or one-platform-SG-per-VPC design.

## Common failure modes

### Review Gate cannot find `js-yaml`

Expected fix is already in workflow:

```text
npm install js-yaml
NODE_PATH: ${{ github.workspace }}/node_modules
```

If it reappears, verify the install step ran before `actions/github-script`.

### `REVIEW_GATE_PAT` missing

Review Gate should not crash. It should resolve zero authority members and leave status pending.

Fix: add `REVIEW_GATE_PAT` secret.

### Team lookup returns 404 / 403

Likely causes:

- wrong org
- wrong team slug
- PAT owner cannot see the org/team
- PAT lacks org-read scope
- enterprise SSO/token policy blocks the token

Fix by validating:

```text
https://github.aexp.com/orgs/amex-eng/teams/nsae
```

and confirming the PAT owner can view it.

### Slack notification fails

Likely causes:

- missing `SLACK_WEBHOOK_URL`
- webhook blocked in enterprise runner
- notification script regression

Decide whether Slack is required or best-effort before enforcing the check.

### Review Policy Summary comment is missing

Likely causes:

- workflow token cannot write issue/PR comments
- GHE organization restricts Actions token write permissions
- `issues: write` permission is missing or ignored by enterprise policy

Expected behavior:

- Review Gate logs the comment failure
- Review Gate still sets the `Review Gate` commit status
- the PR comment is treated as best-effort until GHE token permissions are fixed

Fix by confirming the workflow can create/update PR comments and that the repo/org allows Actions write permissions for issue comments.

### Validation passes but summary says tenant `default`

This was fixed in the personal repo by tenant-source-aware PR summaries. Confirm the GHE repo includes that commit or later.

### VPC discovery fails

Likely causes:

- no available VPC in that region
- multiple available VPCs in that region
- runner/TFE role lacks EC2 describe permissions

Do not bypass this with broad CIDRs. Fix discovery or define explicit future multi-VPC support.

## Rollback

Personal-repo backup archive created before V2 work:

```text
/root/.openclaw/workspace/backups/aws-security-groups-pre-v2-single-tenant-abc3320.tar.gz
```

Source commit:

```text
abc3320af270f8864170cab2730878c266f1ff43
```

GHE rollback options:

1. Revert the failing cutover PR.
2. Disable branch protection check temporarily only with explicit platform approval.
3. Restore from the archived pre-V2 single-tenant snapshot if a full reset is needed.

## Done criteria

Cutover is considered healthy when:

- tenant-layout validation PR passes
- PR summary displays correct tenant sources
- Review Gate resolves `amex-eng/nsae` members using `REVIEW_GATE_PAT`
- Review Gate posts the `Review Policy Summary` PR comment
- correct approvals satisfy Review Gate
- missing/wrong approvals keep Review Gate pending
- `vpc-endpoints` refs do not require extra review
- cross-tenant refs with grants skip target-owner approval
- cross-tenant refs without grants require target-owner approval
- TFE upload/run succeeds with normalized account config
