# TFE Workspace Automation

Automatic TFE workspace provisioning when a new AWS account submits its first PR.

## How It Works

1. PR adds a new `accounts/<account-id>/security-groups.yaml`
2. GitHub Action detects the new account directory (not present on `main`)
3. Action authenticates to internal auth service using service account credentials
4. Action calls the custom TFE API to create an isolated workspace
5. Workspace is configured with the account ID and dynamic credentials
6. PR comment posted with provisioning status
7. On merge, TFE triggers initial plan/apply

## Required GitHub Secrets

| Secret | Description | Example |
|--------|-------------|---------|
| `TFE_AUTH_URL` | Auth service base URL | `https://authservice.<company>.com` |
| `TFE_AUTH_ENVIRONMENT` | Auth environment header | `E1` |
| `TFE_SERVICE_ID` | Service account ADSid | `svc-sg-platform` |
| `TFE_SERVICE_KEY` | Service account password/key | (sensitive) |
| `TFE_API_URL` | Custom TFE API base URL | `https://cldiac.<company>.com` |
| `TFE_CAR_ID` | CAR ID for workspace provisioning | `<car-id>` |
| `TFE_PROJECT_ID` | TFE project ID | `prj-<project-id>` |
| `TFE_CREDENTIALS_PROVIDER` | Dynamic credentials provider | `aws` |
| `TFE_CREDENTIALS_AUTH` | Dynamic credentials auth identity | `svc-tfe@...iam.gserviceaccount.com` |

## Workspace Naming Convention

Workspaces are created with the suffix `sg-<account-id>`:
- Account `847291036584` → workspace suffix `sg-847291036584`

## What Gets Configured

- Workspace created in the specified TFE project
- VCS repository attached (this repo)
- Dynamic credentials configured for the target cloud provider
- `account_id` Terraform variable set

## Failure Handling

If provisioning fails:
- PR comment indicates failure with link to workflow logs
- Validation workflow still runs independently (not blocked)
- Platform engineer can provision manually and re-run the workflow
