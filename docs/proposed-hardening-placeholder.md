# Proposed SG Platform Hardening Placeholder

This PR is intentionally a placeholder diff for review/copy-paste. It does not change the current single-tenant operating model or require requesters to use the new fields yet.

## What I would add next

### 1. Ticket metadata

Allow ticket metadata at the SG or rule level:

```yaml
security_groups:
  app-backend:
    description: Backend API service
    owner: payments-platform
    ticket: NETSEC-1234
    ingress:
      - protocol: tcp
        from_port: 8080
        to_port: 8080
        security_groups: [alb-frontend]
        description: HTTP from ALB
        ticket: APP-4567
```

Why: every exception or risky rule needs an audit handle without forcing humans to reverse-engineer PR history later.

### 2. Expiring rules

Allow rule-level `expires_at`:

```yaml
      - protocol: tcp
        from_port: 443
        to_port: 443
        cidr_blocks: [10.20.30.0/24]
        description: Temporary partner test access
        ticket: NETSEC-2345
        expires_at: "2026-09-30"
```

Why: temporary access that never expires is how SG repos slowly become haunted houses with YAML.

### 3. Attachment intent

Allow SG-level `attach_to` metadata:

```yaml
security_groups:
  app-backend:
    description: Backend API service
    attach_to:
      - eks-nodegroup:payments-prod-workers
      - alb:payments-public
```

Why: today the repo creates SGs, but the consumer attachment intent lives elsewhere. Declaring intended attachments gives reviewers a better blast-radius view without turning this repo into the attachment controller yet.

### 4. Rule grouping

Allow rule-level `group` metadata:

```yaml
      - group: database-access
        protocol: tcp
        from_port: 5432
        to_port: 5432
        security_groups: [rds-postgres]
        description: PostgreSQL from app tier
```

Why: grouped rules make PR summaries and future diff comments way easier to read than a flat pile of ports.

## What this placeholder PR actually changes

- Adds optional schema support for `owner`, `ticket`, `attach_to`, `expires_at`, and `group` metadata.
- Validates obvious bad formats while keeping the fields optional.
- Adds example YAML so requesters can see the intended shape.
- Leaves Terraform behavior unchanged for now.

## Follow-up I would do after this

1. Make PR summaries show ticket, expiry, attachment intent, and group.
2. Add Review Gate escalation for expired/high-risk temporary rules.
3. Add a scheduled stale-rule report for expired `expires_at` values.
4. Eventually require `ticket` + `expires_at` for broad CIDR ingress or temporary exceptions.
