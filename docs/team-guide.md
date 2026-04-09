# Team Guide - Requesting Security Groups

## Quick Start

1. Copy the example:
   ```bash
   cp -r accounts/_example accounts/<your-account-id>
   ```

2. Edit `accounts/<your-account-id>/security-groups.yaml`:
   ```yaml
   account_id: "123456789012"
   environment: "prod"
   carid: "600001725"
   default_region: "us-east-1"

   security_groups:
     my-app-db-access:
       description: "My app database connectivity"
       egress:
         - protocol: "tcp"
           from_port: 5432
           to_port: 5432
           security_groups: ["rds-postgres"]
           description: "PostgreSQL access"
   ```

   > **Note:** Corporate mandatory tags are auto-generated from your `environment` and `carid` fields.
   > You do **not** need to specify them per security group.

3. Open a PR to `main`.

4. Validation runs automatically - fix any errors and push.

5. Once approved and merged, Terraform Enterprise deploys your SGs.

## YAML Schema

```yaml
account_id: "123456789012"          # Required: 12-digit AWS account ID
environment: "prod"                 # Required: prod | test | dev
carid: "600001725"                  # Required: your application's CARID
default_region: "us-east-1"         # Optional: default region for SGs (defaults to us-east-1)

# Corporate mandatory tags are AUTO-GENERATED from environment + carid.
# Do NOT specify them per security group - they are computed by the platform.

security_groups:
  sg-name:                           # Name becomes the SG name prefix
    description: "What this SG is for"
    region: "us-west-2"             # Optional: override default_region for this SG
    tags:                            # Optional: additional custom tags (NOT corporate mandatory)
      team: "payments"
    ingress:                         # Inbound rules
      - protocol: "tcp"
        from_port: 443
        to_port: 443
        cidr_blocks: ["10.0.0.0/8"]             # CIDR source
        # security_groups: ["sg-abc123"]         # OR SG reference
        # prefix_list_ids: ["corporate-networks"] # OR prefix list
        # self: true                              # OR self-reference
        description: "Why this rule exists"
    egress:                          # Outbound rules (same format as ingress)
      - protocol: "tcp"
        from_port: 443
        to_port: 443
        prefix_list_ids: ["corporate-networks"]
        description: "On-prem services via TGW"
```

## Available Prefix Lists

| Name | Description |
|---|---|
| `corporate-networks` | Corporate offices + VPN |
| `waf-saas-providers` | Cloudflare, Fastly ranges |

## What Gets Blocked

- `0.0.0.0/0` ingress (egress allowed only for HTTPS/443)
- Ports 23 (Telnet), 135 (RPC), 139 (NetBIOS), 445 (SMB)
- Port ranges wider than 1000 ports
- Database ports from wide CIDRs (warning)
- SSH/RDP from CIDRs (warning) - use Session Manager
- Duplicate rules
- Unknown/misspelled YAML keys

## Validation

Run locally before pushing:
```bash
python scripts/validate.py accounts/<your-account-id>
```
