# Terraform Cloud backend
# Each account gets a workspace: sg-baseline-{account_id}

terraform {
  cloud {
    organization = "ORGANIZATION_NAME"

    workspaces {
      name = "sg-platform-baseline"
    }
  }
}
