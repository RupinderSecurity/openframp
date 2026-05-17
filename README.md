# OpenFRAMP

Open-source multi-framework, multi-cloud compliance scanner that runs inside authorization boundaries where SaaS tools cannot operate.

## The Problem

FedRAMP Government Cloud environments are strict authorization boundaries. Commercial compliance platforms like Vanta, Drata, and Secureframe are SaaS products — they sit outside the boundary. To use them inside a FedRAMP environment, the tool itself would need FedRAMP authorization, creating a circular dependency. Most organizations resort to manual evidence collection: screenshots, spreadsheets, and point-in-time assessments.

## What OpenFRAMP Does

OpenFRAMP is a self-contained compliance pipeline that runs entirely inside your boundary. No external SaaS dependencies. No data leaves the environment.

- **140 compliance checks** across 3 cloud providers
- **3 frameworks simultaneously** — FedRAMP Moderate, PCI DSS 4.0.1, SOC 2
- **SSP parser** — converts FedRAMP SSP Appendix A Word docs to OSCAL JSON
- **Web dashboard** with provider tabs, scan trigger, SSP upload, and PDF export
- **OSCAL native** — generates Assessment Results in the format NIST mandates for FedRAMP
- **Docker deployment** — one command to start scanning
- **Catalog-driven** — add checks by editing JSON, no code changes

## Quick Start

### Docker Compose (recommended)

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
```

Create a `.env` file with cloud credentials:

```
AZURE_CLIENT_ID=your-app-id
AZURE_CLIENT_SECRET=your-secret
AZURE_TENANT_ID=your-tenant-id
GITHUB_TOKEN=your-github-token
```

```bash
docker compose build
docker compose up -d
```

Open `http://localhost:4000`. Click "Run Scan."

### Run locally

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
./scan.sh                                        # scan all providers
./scan.sh catalog/fedramp-moderate-aws.json      # AWS only
./scan.sh catalog/fedramp-moderate-azure.json    # Azure only
./scan.sh catalog/github-security.json           # GitHub only
```

See [INSTALL.md](INSTALL.md) for full setup instructions.

## Coverage

### AWS — 32 controls, 78 checks

| Family | Controls |
| --- | --- |
| Access Control | AC-2, AC-3, AC-4, AC-6, AC-7, AC-17 |
| Audit & Accountability | AU-2, AU-3, AU-6, AU-9, AU-11, AU-12 |
| Configuration Management | CM-2, CM-6, CM-7, CM-8 |
| Contingency Planning | CP-9, CP-10 |
| Identification & Auth | IA-2, IA-5 |
| Incident Response | IR-6 |
| Risk Assessment | RA-5 |
| System & Comm Protection | SC-7, SC-8, SC-12, SC-13, SC-23, SC-28 |
| System & Info Integrity | SI-2, SI-3, SI-4, SI-7 |

Checks include: S3 public access/encryption/versioning/logging, IAM MFA/least privilege/key rotation, CloudTrail logging/encryption, security groups, VPC flow logs, KMS key management, GuardDuty, SecurityHub, Secrets Manager, Lambda, EBS, RDS, ECR, CloudWatch logs, and more.

### Azure + Entra ID — 15 controls, 41 checks

| Family | Controls |
| --- | --- |
| Access Control | AC-2, AC-3, AC-6, AC-17 |
| Audit & Accountability | AU-2, AU-9 |
| Configuration Management | CM-6 |
| Contingency Planning | CP-9 |
| Identification & Auth | IA-2, IA-5 |
| System & Comm Protection | SC-7, SC-8, SC-12, SC-28 |
| System & Info Integrity | SI-4 |

Checks include: Storage account encryption/TLS/public access, Key Vault soft delete/purge protection/key expiry, NSG rules (SSH/RDP open to internet), Entra ID users/groups/roles, conditional access, security defaults, audit logs, sign-in reports, guest invite policies.

### GitHub — 9 controls, 21 checks

| Family | Controls |
| --- | --- |
| Access Control | AC-3, AC-6 |
| Audit & Accountability | AU-2 |
| Configuration Management | CM-2, CM-3, CM-7 |
| Risk Assessment | RA-5 |
| System Acquisition | SA-11 |
| System & Info Integrity | SI-7 |

Checks include: Branch protection (force push, deletions, PR reviews, status checks, signed commits, code owner reviews), Dependabot alerts, security policy, wiki settings, repository visibility, license compliance.

Every check maps to **FedRAMP Moderate**, **PCI DSS 4.0.1**, and **SOC 2** simultaneously with FedRAMP 20x KSI references.

## Web Dashboard

The dashboard at `localhost:4000` provides:

- **Provider tabs** — filter by AWS, Azure & Entra ID, or GitHub
- **Run Scan** — trigger a live scan from the browser
- **Upload SSP** — parse FedRAMP SSP Appendix A (.docx) into OSCAL SSP JSON with 323 controls
- **Export PDF** — download a compliance report with executive summary, severity breakdown, and per-provider findings
- **SSP tab** — shows parsed SSP controls grouped by family with completion tracking
- **Expandable controls** — click to see findings with resource names and severity badges
- **Progress bar** — compliance posture at a glance

## Architecture

```
openframp/
├── catalog/                             # Control definitions (add checks here)
│   ├── fedramp-moderate-aws.json        #   AWS: 32 controls, 78 checks
│   ├── fedramp-moderate-azure.json      #   Azure + Entra ID: 15 controls, 41 checks
│   └── github-security.json             #   GitHub: 9 controls, 21 checks
├── oscal/
│   ├── scanner.py                       #   Catalog-driven scan engine
│   └── assessment-results-*.json        #   Generated OSCAL output (per provider)
├── ssp-parser/
│   ├── ssp_parser.py                    #   Parses 323 controls from SSP Appendix A
│   └── ssp_to_oscal.py                  #   Converts to OSCAL 1.1 SSP JSON
├── web/
│   ├── app.py                           #   Flask API (scan, upload, export)
│   └── static/index.html               #   Dashboard UI
├── bootstrap/
│   ├── scanner-iam/                     #   AWS IAM User (OpenTofu)
│   └── scanner-role/                    #   AWS IAM Role with AssumeRole (OpenTofu)
├── scan.sh                              # CLI entry point
├── Dockerfile                           # Container image
├── docker-compose.yml                   # One-command deployment
└── .env                                 # Cloud credentials (gitignored)
```

### Catalog-driven design

Adding a new check = adding JSON. No code changes:

```json
{
  "check_id": "sc-28-s3-encryption",
  "description": "S3 buckets should have encryption enabled",
  "severity": "high",
  "query": "select name, server_side_encryption_configuration from aws_s3_bucket",
  "fedramp_20x_ksi": ["KSI-CRY-01"]
}
```

New cloud provider = new catalog file, same engine.

## Roadmap

### Completed
- [x] AWS: 32 controls, 78 checks across 10 control families
- [x] Azure + Entra ID: 15 controls, 41 checks
- [x] GitHub: 9 controls, 21 checks
- [x] Multi-framework mapping (FedRAMP + PCI DSS + SOC 2)
- [x] FedRAMP 20x KSI coverage (28/61 Moderate KSIs)
- [x] SSP docx parser (323 FedRAMP Moderate controls)
- [x] OSCAL SSP and Assessment Results generation
- [x] Web dashboard with provider tabs, scan trigger, SSP upload
- [x] PDF compliance report export
- [x] IAM Role with AssumeRole (no long-lived secrets)
- [x] Azure Service Principal for Docker scanning
- [x] Docker Compose deployment
- [x] Catalog-driven architecture
- [x] Branch protection, secret scanning, Dependabot, SECURITY.md

### Planned
- [ ] GCP catalog
- [ ] Remediation guidance per finding
- [ ] CI/CD with OIDC for scheduled scans
- [ ] Multi-account/multi-org scanning
- [ ] Contributing guide for community catalogs

## What V1 Does NOT Do

- **Remediation**: Reports findings but does not fix them
- **Continuous monitoring**: Point-in-time scans, not real-time
- **GCP**: AWS, Azure, and GitHub only
- **FedRAMP High/Low**: Moderate baseline only
- **Multi-tenant**: Single-user, single-scan
- **Non-cloud controls**: Physical security, personnel, training are not automatable

## License

MIT

## Author

[Rupinder Pal Singh](https://github.com/RupinderSecurity) — Manager, Information Security | CISSP, CISM, CISA, CRISC
