# Architecture

How OpenFRAMP works, why it's built this way, and how the pieces fit together.

## Pipeline Overview

OpenFRAMP has two independent pipelines that produce OSCAL output:

```
Pipeline 1: SSP Parsing
──────────────────────────────────────────────────────────
FedRAMP SSP          Structured           OSCAL 1.1
Appendix A    →    JSON with 323    →    SSP JSON
(.docx)            controls parsed        document

Pipeline 2: Infrastructure Scanning
──────────────────────────────────────────────────────────
Cloud               Steampipe          Scanner           OSCAL 1.1
Infrastructure  →   SQL queries   →    engine     →    Assessment
(AWS, Azure,        via catalogs       evaluation       Results JSON
 GitHub)

Pipeline 3: Web Dashboard
──────────────────────────────────────────────────────────
OSCAL JSON    →    Flask API    →    Browser dashboard
                                     with provider tabs,
                                     scan trigger, SSP upload
```

## Directory Structure

```
openframp/
├── catalog/                             # Control definitions
│   ├── fedramp-moderate-aws.json        #   AWS: 31 controls, 57 checks
│   ├── fedramp-moderate-azure.json      #   Azure + Entra ID: 15 controls, 28 checks
│   └── github-security.json             #   GitHub: 9 controls, 16 checks
│
├── oscal/                               # Scanner engine and output
│   ├── scanner.py                       #   Catalog-driven scan engine
│   ├── assessment-results-aws.json      #   Generated OSCAL (per provider)
│   ├── assessment-results-azure.json    #
│   └── assessment-results-github.json   #
│
├── ssp-parser/                          # SSP document parsing
│   ├── ssp_parser.py                    #   Extracts 323 controls from Appendix A
│   ├── ssp_to_oscal.py                  #   Converts to OSCAL 1.1 SSP JSON
│   └── (template docs)                  #   FedRAMP SSP templates (not committed)
│
├── web/                                 # Web dashboard
│   ├── app.py                           #   Flask API (scan trigger, SSP upload, results)
│   └── static/index.html               #   Dashboard UI (provider tabs, findings)
│
├── checks/                              # Legacy OPA/Rego policies (still usable)
│
├── bootstrap/                           # Infrastructure as code
│   ├── scanner-iam/                     #   AWS IAM User (static credentials)
│   └── scanner-role/                    #   AWS IAM Role (temporary credentials)
│
├── scan.sh                              # CLI entry point
├── Dockerfile                           # Container image
├── docker-compose.yml                   # One-command deployment
└── .env                                 # Cloud credentials (gitignored)
```

## Design Decisions

### Why catalog-driven?

Each check is a JSON entry with a control ID, description, severity, SQL query, and framework mappings. Adding a new check means adding JSON — no code changes to the scanner engine. This scaled OpenFRAMP from 6 hand-written checks to 101 checks across 3 providers in days.

The tradeoff: evaluation logic lives in Python pattern matching rather than declarative Rego policies. The planned future architecture combines both — catalogs define what to check, Rego files define how to evaluate for critical controls.

### Why Steampipe?

Steampipe turns cloud APIs into SQL tables. One tool queries AWS, Azure, GitHub, and 140+ other services with the same interface. Alternatives and why they were not chosen:

- **Prowler**: Predefined checks only. Cannot add custom checks or map to arbitrary frameworks.
- **Cloud Custodian**: Primarily a policy enforcement engine that modifies resources. OpenFRAMP is read-only by design.
- **AWS Config / Azure Policy**: Vendor-locked. OpenFRAMP scans three providers from one engine.
- **Custom API calls**: Steampipe handles pagination, rate limiting, and caching.

### Why run inside the boundary?

SaaS compliance tools operate outside the FedRAMP authorization boundary. For them to scan inside, they would need their own FedRAMP authorization. OpenFRAMP runs as a container inside the boundary with no external dependencies.

### Why OSCAL?

NIST mandates OSCAL for FedRAMP by September 2026. OpenFRAMP generates OSCAL Assessment Results natively, producing machine-readable evidence that feeds directly into the authorization process.

### Why three separate output files?

Each provider gets its own OSCAL Assessment Results file (`assessment-results-aws.json`, `assessment-results-azure.json`, `assessment-results-github.json`). The web dashboard combines them for display but keeps them separate on disk. This allows scanning providers independently and comparing results across time.

### Why IAM Role over IAM User?

The role-based approach uses AssumeRole for temporary credentials that expire in 1 hour. No long-lived secrets to rotate. The scanner user's static key only calls `sts:AssumeRole`, never accesses AWS services directly.

### Why Azure Service Principal?

Azure CLI tokens are session-based and machine-specific. They don't work reliably in Docker containers. A service principal with `Reader` role + Microsoft Graph permissions provides stable, credential-based authentication that works in any environment.

## Catalog Schema

```json
{
  "catalog_version": "1.0.0",
  "framework": "Multi-Framework",
  "baseline": "FedRAMP Moderate + PCI DSS 4.0.1 + SOC 2",
  "provider": "aws",
  "controls": [
    {
      "control_id": "SC-28",
      "title": "Protection of Information at Rest",
      "family": "System and Communications Protection",
      "frameworks": ["FedRAMP SC-28", "PCI DSS 3.5.2", "SOC 2 CC6.1"],
      "checks": [
        {
          "check_id": "sc-28-s3-encryption",
          "description": "S3 buckets should have encryption enabled",
          "severity": "high",
          "query": "select name, server_side_encryption_configuration from aws_s3_bucket",
          "resource_type": "aws_s3_bucket",
          "fedramp_20x_ksi": ["KSI-CRY-01"]
        }
      ]
    }
  ]
}
```

Adding a new check requires only adding a JSON entry. The scanner engine processes it automatically.

## Scanner Engine

`oscal/scanner.py` reads any catalog file, runs each query via Steampipe, evaluates results with pattern matching, and generates OSCAL output. Error handling:

- **Service not enabled** (GuardDuty, SecurityHub): reported as a finding
- **Service not available** (Redshift in Free Tier): reported as a finding
- **Dependabot alerts disabled**: reported as a finding
- **Query errors**: counted separately, not confused with findings

## Web Dashboard

`web/app.py` is a Flask application serving the dashboard on port 4000.

**API endpoints:**
- `GET /api/results?provider=all|aws|azure|github` — returns OSCAL results, optionally filtered
- `POST /api/scan` — triggers a scan (accepts `{"catalog": "all"}` or specific catalog filename)
- `GET /api/catalogs` — lists available catalogs
- `POST /api/upload-ssp` — accepts a `.docx` file, parses it, generates OSCAL SSP
- `GET /api/ssp-results` — returns parsed SSP data

The dashboard renders provider tabs dynamically. Adding a new provider catalog automatically creates a new tab.

## Docker Architecture

`docker-compose.yml` runs a single container that includes Steampipe (with AWS, Azure, Entra ID, and GitHub plugins), Flask, OPA, and all catalogs. Cloud credentials are passed via environment variables from `.env` and volume mounts.

```yaml
services:
  openframp:
    build: .
    ports:
      - "4000:4000"
    volumes:
      - ~/.aws:/home/scanner/.aws:ro
    environment:
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - GITHUB_TOKEN=${GITHUB_TOKEN}
    entrypoint: ["python3", "/home/scanner/openframp/web/app.py"]
```

## What V1 Does NOT Do

- **Multi-tenant**: Single-user, single-scan. No user management.
- **Continuous monitoring**: Run-once, produce-report. CI/CD scheduling is documented but not built in.
- **Remediation automation**: Reports findings. Does not fix them.
- **GCP**: AWS, Azure, and GitHub only. GCP requires a new catalog.
- **FedRAMP High/Low**: Moderate baseline only.
- **Non-cloud controls**: Physical security, personnel security, and other non-technical controls are not automatable.
- **POA&M generation**: Produces Assessment Results but not Plans of Action.
- **Multi-account scanning**: Scans one AWS account, one Azure subscription, one GitHub owner at a time.
