# OpenFRAMP

Open-source multi-framework, multi-cloud compliance scanner that runs inside authorization boundaries where SaaS tools cannot operate.

## The Problem

FedRAMP Government Cloud environments are strict authorization boundaries. Commercial compliance platforms like Vanta, Drata, and Secureframe are SaaS products — they sit outside the boundary. To use them inside a FedRAMP environment, the tool itself would need FedRAMP authorization, creating a circular dependency. Most organizations resort to manual evidence collection: screenshots, spreadsheets, and point-in-time assessments.

## What OpenFRAMP Does

OpenFRAMP is a self-contained compliance pipeline that runs entirely inside your boundary. No external SaaS dependencies. No data leaves the environment.

```
Catalog (JSON control definitions per cloud provider)
    → Steampipe (cloud data collection via SQL)
        → Scanner engine (policy evaluation)
            → OSCAL Assessment Results (standardized output)
```

- **Multi-cloud** — AWS and Azure/Entra ID from a single engine
- **Multi-framework** — FedRAMP Moderate, PCI DSS 4.0.1, and SOC 2 simultaneously
- **Catalog-driven** — add checks by editing JSON, no code changes
- **OSCAL native** — generates Assessment Results in the format NIST mandates for FedRAMP by September 2026
- **Runs anywhere** — locally, in Docker, or inside your authorization boundary

## Current Coverage

**46 controls | 85 checks | 2 cloud providers | 3 frameworks**

### AWS (31 controls, 57 checks)

| Family | Controls |
| --- | --- |
| Access Control | AC-2, AC-3, AC-4, AC-6, AC-7, AC-17 |
| Audit & Accountability | AU-2, AU-3, AU-6, AU-9, AU-11 |
| Configuration Management | CM-2, CM-6, CM-7, CM-8 |
| Contingency Planning | CP-9, CP-10 |
| Identification & Auth | IA-2, IA-5 |
| Incident Response | IR-6 |
| Risk Assessment | RA-5 |
| System & Comm Protection | SC-7, SC-8, SC-12, SC-13, SC-23, SC-28 |
| System & Info Integrity | SI-2, SI-3, SI-4, SI-7 |

### Azure + Entra ID (15 controls, 28 checks)

| Family | Controls |
| --- | --- |
| Access Control | AC-2, AC-3, AC-6, AC-17 |
| Audit & Accountability | AU-2, AU-9 |
| Configuration Management | CM-6 |
| Contingency Planning | CP-9 |
| Identification & Auth | IA-2, IA-5 |
| System & Comm Protection | SC-7, SC-8, SC-12, SC-28 |
| System & Info Integrity | SI-4 |

Every check maps to **FedRAMP Moderate**, **PCI DSS 4.0.1**, and **SOC 2** simultaneously.

## Quick Start

### Run with Docker (recommended, no dependencies)

```bash
docker build -t openframp .
docker run --rm -v ~/.aws:/home/scanner/.aws:ro openframp
```

### Run locally

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
./scan.sh                                        # scan all catalogs
./scan.sh catalog/fedramp-moderate-aws.json      # AWS only
./scan.sh catalog/fedramp-moderate-azure.json    # Azure only
```

### Prerequisites (local runs)

- [Steampipe](https://steampipe.io/) with AWS and/or Azure plugins
- Python 3.9+
- Cloud credentials configured (AWS CLI and/or Azure CLI)

## Architecture

```
openframp/
├── catalog/
│   ├── fedramp-moderate-aws.json      ← AWS (31 controls, 57 checks)
│   └── fedramp-moderate-azure.json    ← Azure + Entra ID (15 controls, 28 checks)
├── oscal/
│   ├── scanner.py                     ← Generic scan engine (reads any catalog)
│   └── assessment-results.json        ← Generated OSCAL output
├── bootstrap/
│   ├── scanner-iam/                   ← AWS IAM User (OpenTofu)
│   └── scanner-role/                  ← AWS IAM Role with AssumeRole (OpenTofu)
├── scan.sh                            ← Entry point
└── Dockerfile                         ← Containerized deployment
```

### Catalog-driven design

Adding a new check means adding JSON — no code changes:

```json
{
  "check_id": "sc-28-s3-encryption",
  "description": "S3 buckets should have encryption enabled",
  "severity": "high",
  "query": "select name, server_side_encryption_configuration from aws_s3_bucket"
}
```

New cloud provider = new catalog file, same engine.

## Roadmap

### Completed
- [x] AWS: 31 controls, 57 checks, 9 control families
- [x] Azure + Entra ID: 15 controls, 28 checks
- [x] Multi-framework (FedRAMP + PCI DSS + SOC 2)
- [x] IAM Role with AssumeRole (no long-lived secrets)
- [x] Docker container
- [x] OSCAL Assessment Results generation

### Planned
- [ ] Expand Azure catalog to match AWS depth
- [ ] GCP catalog
- [ ] GitHub/GitLab security configuration catalog
- [ ] OSCAL Viewer dashboard
- [ ] CI/CD with OIDC for scheduled scans
- [ ] Remediation guidance per finding
- [ ] OSCAL SSP parser

## License

MIT

## Author

[Rupinder Pal Singh](https://github.com/RupinderSecurity) — Manager, Information Security
