# AWS Security Group Platform - Naming Conventions

This document defines the naming standards and conventions used throughout the AWS Security Group platform to ensure consistency, clarity, and maintainability.

## 📋 Table of Contents

1. [General Principles](#general-principles)
2. [Security Group Names](#security-group-names)
3. [Tag Standards](#tag-standards)
4. [Prefix List Names](#prefix-list-names)
5. [Directory Structure](#directory-structure)
6. [Rule Descriptions](#rule-descriptions)
7. [Examples](#examples)
8. [Validation Rules](#validation-rules)

## 🎯 General Principles

### Core Guidelines

1. **Consistency**: Use the same patterns across all accounts and environments
2. **Clarity**: Names should clearly indicate purpose and scope
3. **Brevity**: Keep names concise while maintaining clarity
4. **Hierarchy**: Use prefixes to group related resources
5. **Environment Awareness**: Include environment context where relevant

### Character Rules

- **Allowed Characters**: Lowercase letters (`a-z`), numbers (`0-9`), hyphens (`-`)
- **Start/End**: Must begin and end with alphanumeric characters
- **No Spaces**: Use hyphens instead of spaces or underscores
- **Case**: Always lowercase for consistency

### Length Limits

- **Security Groups**: Maximum 63 characters (AWS limit: 255, our standard: 63)
- **Tags**: Key names up to 128 characters, values up to 256 characters
- **Descriptions**: Maximum 255 characters, recommend under 100 for readability

## 🔒 Security Group Names

### Standard Pattern

```
{service}-{purpose}-{environment}
```

### Components

| Component | Description | Examples | Required |
|-----------|-------------|----------|----------|
| `service` | The service or application | `web`, `api`, `db`, `cache`, `eks` | Yes |
| `purpose` | Specific function or role | `servers`, `nodes`, `proxy`, `lb` | Yes |
| `environment` | Environment designation | `prod`, `staging`, `dev` | Yes |

### Service Categories

| Service | Description | Common Purposes |
|---------|-------------|-----------------|
| `web` | Web servers and frontends | `servers`, `proxy`, `cdn` |
| `api` | API servers and gateways | `servers`, `gateway`, `proxy` |
| `app` | Application servers | `servers`, `workers`, `batch` |
| `db` | Database servers | `postgres`, `mysql`, `redis`, `mongo` |
| `cache` | Caching layers | `redis`, `memcached`, `elasticache` |
| `queue` | Message queues | `sqs`, `rabbitmq`, `kafka` |
| `lb` | Load balancers | `alb`, `nlb`, `elb` |
| `eks` | Kubernetes/EKS | `nodes`, `control`, `ingress` |
| `bastion` | Jump/bastion hosts | `hosts`, `servers` |
| `monitoring` | Observability stack | `prometheus`, `grafana`, `logs` |
| `cicd` | CI/CD infrastructure | `runners`, `agents`, `deploy` |
| `vpn` | VPN infrastructure | `endpoints`, `gateway`, `tunnel` |

### Environment Designations

| Environment | Full Name | Use Case |
|-------------|-----------|----------|
| `prod` | Production | Live customer-facing systems |
| `staging` | Staging/Pre-production | Final testing before production |
| `dev` | Development | Development and testing |
| `qa` | Quality Assurance | QA and testing environments |
| `sandbox` | Sandbox | Experimental and learning |
| `shared` | Shared Resources | Cross-environment resources |

### Examples

```yaml
# Good examples following the pattern:
web-servers-prod           # Production web servers
api-gateway-staging        # Staging API gateway  
db-postgres-dev            # Development PostgreSQL
cache-redis-prod           # Production Redis cache
eks-nodes-staging          # Staging EKS worker nodes
lb-alb-prod               # Production Application Load Balancer
monitoring-prometheus-prod # Production Prometheus
bastion-hosts-shared      # Shared bastion hosts

# Specialized patterns:
web-servers-prod-internal  # Internal-only web servers
api-gateway-prod-public    # Public-facing API gateway
db-postgres-prod-readonly  # Read-only database replicas
```

### Multi-Component Services

For complex applications, use additional descriptors:

```yaml
# Pattern: {service}-{component}-{purpose}-{environment}
ecommerce-web-servers-prod      # E-commerce web servers
ecommerce-api-servers-prod      # E-commerce API servers
ecommerce-db-postgres-prod      # E-commerce PostgreSQL database

# Pattern: {service}-{purpose}-{variant}-{environment}
web-servers-public-prod         # Public web servers
web-servers-internal-prod       # Internal web servers
api-servers-external-prod       # External API servers
api-servers-internal-prod       # Internal API servers
```

## 🏷️ Tag Standards

### Required Tags

Every security group must have these tags:

| Tag Key | Description | Example | Validation |
|---------|-------------|---------|------------|
| `ManagedBy` | Management system | `sg-platform` | Auto-added |
| `Team` | Owning team | `backend`, `frontend`, `data` | Required |
| `Environment` | Environment tier | `production`, `staging`, `development` | Required |
| `Application` | Application name | `order-service`, `user-api` | Required |

### Recommended Tags

| Tag Key | Description | Example | Use Case |
|---------|-------------|---------|----------|
| `Purpose` | Specific function | `web-servers`, `database` | Resource grouping |
| `CostCenter` | Billing allocation | `engineering`, `marketing` | Cost tracking |
| `Project` | Project identifier | `migration-2024`, `new-feature` | Project tracking |
| `Owner` | Technical owner | `john.doe@company.com` | Contact information |
| `Backup` | Backup requirement | `daily`, `none` | Backup policies |
| `Monitoring` | Monitoring tier | `critical`, `standard`, `basic` | Alerting levels |
| `Compliance` | Compliance requirements | `pci`, `hipaa`, `sox` | Compliance tracking |

### Tag Value Conventions

**Team Names**:
```yaml
# Use consistent team identifiers:
Team: "backend"        # Backend engineering team
Team: "frontend"       # Frontend engineering team  
Team: "data"          # Data engineering team
Team: "platform"      # Platform/infrastructure team
Team: "security"      # Security team
Team: "devops"        # DevOps/SRE team
```

**Application Names**:
```yaml
# Use kebab-case for multi-word applications:
Application: "order-service"
Application: "user-management"
Application: "payment-gateway"
Application: "inventory-system"
```

**Environment Values**:
```yaml
# Use full environment names for clarity:
Environment: "production"    # Not "prod"
Environment: "staging"      # Not "stage"  
Environment: "development"  # Not "dev"
```

### Tag Examples

```yaml
# Complete tag set example:
tags:
  ManagedBy: "sg-platform"           # Auto-added by platform
  Team: "backend"                    # Required
  Environment: "production"          # Required
  Application: "order-service"       # Required
  Purpose: "api-servers"            # Recommended
  CostCenter: "engineering"         # Recommended
  Project: "microservices-migration" # Optional
  Owner: "backend-team@company.com"  # Optional
  Compliance: "pci"                 # Optional
  Monitoring: "critical"            # Optional
```

## 📂 Prefix List Names

Prefix lists use a descriptive naming pattern:

### Pattern
```
{category}-{purpose}
```

### Categories

| Category | Description | Examples |
|----------|-------------|----------|
| `corporate` | Company networks | `corporate-networks`, `corporate-vpn` |
| `aws` | AWS service ranges | `aws-vpc-endpoints`, `aws-cloudfront` |
| `waf` | WAF provider IPs | `waf-saas-providers`, `waf-cloudflare` |
| `cdn` | CDN provider IPs | `cdn-cloudflare`, `cdn-fastly` |
| `cicd` | CI/CD system IPs | `cicd-github-actions`, `cicd-jenkins` |
| `monitoring` | Monitoring service IPs | `monitoring-datadog`, `monitoring-newrelic` |
| `database` | Database subnet ranges | `database-subnets`, `database-backup` |
| `application` | Application subnet ranges | `app-subnets`, `app-private` |

### Examples

```yaml
# Network ranges:
corporate-networks        # Corporate office networks
corporate-vpn            # Corporate VPN ranges
database-subnets         # Database subnet CIDRs
app-private-subnets      # Private application subnets
alb-subnets             # Load balancer subnets

# External services:
waf-saas-providers      # WAF service provider IPs
cdn-cloudflare          # Cloudflare CDN ranges
monitoring-datadog      # DataDog monitoring IPs
cicd-github-actions     # GitHub Actions runner IPs

# AWS services:
aws-vpc-endpoints       # AWS VPC endpoint ranges
aws-s3-service         # AWS S3 service ranges
aws-cloudfront         # AWS CloudFront ranges
```

## 📁 Directory Structure

### Account Directories

Account directories follow AWS account ID format:

```
accounts/
├── 111111111111/          # Production account (12-digit account ID)
├── 222222222222/          # Staging account
├── 333333333333/          # Development account
├── _example/              # Example configuration (underscore prefix)
└── README.md             # Account directory documentation
```

### Environment-Based Naming

Alternative approach using descriptive names:

```
accounts/
├── production/
│   ├── security-groups.yaml
│   └── terraform/
├── staging/
│   ├── security-groups.yaml
│   └── terraform/
└── development/
    ├── security-groups.yaml
    └── terraform/
```

### File Naming

| File | Purpose | Required |
|------|---------|----------|
| `security-groups.yaml` | Main configuration | Yes |
| `terraform/` | Generated Terraform files | Auto-generated |
| `README.md` | Account-specific documentation | Recommended |
| `.gitignore` | Ignore patterns | Optional |

## 📝 Rule Descriptions

### Description Patterns

Use clear, actionable descriptions following this pattern:

```
{protocol} {direction} {source/destination} for {purpose}
```

### Examples

```yaml
# Good descriptions:
description: "HTTPS from ALB to backend API servers"
description: "PostgreSQL from application servers to RDS"
description: "SSH from bastion hosts for administration"
description: "Health checks from load balancer to web servers"
description: "Inter-node communication for EKS cluster"
description: "DNS resolution to VPC endpoints"

# Avoid vague descriptions:
description: "Web traffic"           # Too vague
description: "Database access"       # Too generic
description: "HTTP"                 # Missing context
description: "Port 80"              # Doesn't explain purpose
```

### Description Components

| Component | Description | Examples |
|-----------|-------------|----------|
| **Protocol** | Network protocol | `HTTPS`, `PostgreSQL`, `SSH`, `DNS` |
| **Direction** | Traffic flow | `from`, `to`, `between` |
| **Source/Dest** | Traffic endpoints | `ALB`, `application servers`, `bastion hosts` |
| **Purpose** | Business reason | `for API access`, `for administration`, `for health checks` |

### Template Descriptions

Common patterns you can reuse:

```yaml
# Web traffic:
description: "HTTP from load balancer to web servers"
description: "HTTPS from WAF to application servers" 
description: "Health checks from ALB to backend services"

# Database access:
description: "PostgreSQL from application servers to RDS"
description: "Redis from cache clients to ElastiCache"
description: "MongoDB from application to document database"

# Administrative access:
description: "SSH from bastion hosts for server administration"
description: "RDP from jump server for Windows administration"
description: "HTTPS from corporate networks for web console access"

# Monitoring and logging:
description: "Metrics collection from Prometheus to application servers"
description: "Log forwarding from applications to central logging"
description: "SNMP monitoring from monitoring servers"

# Inter-service communication:
description: "API calls between microservices"
description: "Message queue access from producers to RabbitMQ"
description: "Service discovery from applications to Consul"

# Kubernetes/EKS:
description: "Kubelet API from control plane to worker nodes"
description: "Inter-pod communication within EKS cluster"
description: "Ingress controller to application pods"
```

## ✅ Examples

### Complete Security Group Example

```yaml
# Security group name: api-gateway-prod
api-gateway-prod:
  description: "Production API gateway security group for external traffic"
  
  # Complete tag set following conventions
  tags:
    ManagedBy: "sg-platform"           # Auto-added
    Team: "backend"                    # Required - owning team
    Environment: "production"          # Required - environment
    Application: "api-gateway"         # Required - application name
    Purpose: "external-api"           # Recommended - specific purpose
    CostCenter: "engineering"         # Recommended - billing
    Project: "api-modernization"      # Optional - current project
    Owner: "api-team@company.com"     # Optional - contact
    Compliance: "pci"                 # Optional - compliance needs
    Monitoring: "critical"            # Optional - monitoring level
  
  ingress:
    # Well-described rules following description pattern
    - protocol: "tcp"
      from_port: 443
      to_port: 443
      prefix_list_ids: ["waf-saas-providers"]
      description: "HTTPS from WAF providers to API gateway"
    
    - protocol: "tcp"
      from_port: 80
      to_port: 80
      prefix_list_ids: ["waf-saas-providers"]
      description: "HTTP redirect from WAF providers to API gateway"
    
    - protocol: "tcp"
      from_port: 8080
      to_port: 8080
      security_groups: ["lb-alb-prod"]
      description: "Health checks from ALB to API gateway"
  
  egress:
    - protocol: "tcp"
      from_port: 443
      to_port: 443
      security_groups: ["app-backend-prod"]
      description: "HTTPS to backend services for API processing"
    
    - protocol: "tcp"
      from_port: 5432
      to_port: 5432
      prefix_list_ids: ["database-subnets"]
      description: "PostgreSQL to RDS for API data access"
```

## 🔍 Validation Rules

The platform automatically enforces these naming conventions:

### Security Group Names

```python
# Validation regex pattern:
security_group_pattern = "^[a-z0-9][a-z0-9-]*[a-z0-9]$"

# Maximum length:
max_name_length = 63

# Examples that pass:
"web-servers-prod"        ✅
"api-gateway-staging"     ✅  
"db-postgres-dev"         ✅
"eks-nodes-production"    ✅

# Examples that fail:
"Web-Servers-Prod"        ❌ (uppercase)
"web_servers_prod"        ❌ (underscores)
"web servers prod"        ❌ (spaces)
"-web-servers-prod"       ❌ (starts with hyphen)
"web-servers-prod-"       ❌ (ends with hyphen)
"a"                       ❌ (too short, but technically valid)
```

### Required Tags

```yaml
# These tags are automatically validated:
required_tags:
  - "ManagedBy"      # Auto-added as "sg-platform"
  - "Team"           # Must be provided
  - "Environment"    # Must be provided
  - "Application"    # Must be provided

# Validation will fail if any required tag is missing
```

### Tag Value Validation

```yaml
# Environment values must be from approved list:
valid_environments:
  - "production"
  - "staging" 
  - "development"
  - "qa"
  - "sandbox"
  - "shared"

# Team names should be lowercase and descriptive
valid_team_pattern = "^[a-z][a-z0-9-]*$"
```

### Description Validation

```python
# Minimum description length:
min_description_length = 10

# Maximum description length:
max_description_length = 255

# Required: All rules must have descriptions
# Good: "HTTPS from ALB to backend API servers"
# Bad: "HTTP" (too short)
# Bad: "" (empty)
```

## 🚀 Best Practices

### Naming Strategy

1. **Start Simple**: Begin with the basic pattern, add complexity as needed
2. **Be Consistent**: Use the same patterns across all teams and accounts  
3. **Document Decisions**: Record naming decisions in team documentation
4. **Review Regularly**: Periodically review and update naming conventions

### Evolution Guidelines

1. **Backward Compatibility**: Don't break existing naming when updating
2. **Migration Path**: Provide clear migration path for legacy names
3. **Team Alignment**: Get team buy-in before changing conventions
4. **Gradual Adoption**: Phase in new conventions over time

### Common Mistakes

1. **Inconsistent Casing**: Mixing uppercase and lowercase
2. **Abbreviations**: Using unclear abbreviations (`svc` vs `service`)
3. **Environment Confusion**: Using `prod` vs `production` inconsistently
4. **Missing Context**: Names that don't indicate environment or purpose
5. **Too Long**: Names that hit character limits
6. **Too Generic**: Names that don't distinguish between similar resources

---

## 📚 Related Documentation

- [Team Guide](team-guide.md) - Complete usage guide
- [Example Configurations](examples/) - Working examples  
- [Troubleshooting Guide](team-guide.md#troubleshooting) - Common issues

---

**Questions about naming conventions?**
- Slack: `#security-groups`
- Email: platform-team@company.com