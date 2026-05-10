# OpenFRAMP

Open-source multi-framework, multi-cloud compliance scanner that runs inside authorization boundaries where SaaS tools cannot operate.

## The Problem

FedRAMP Government Cloud environments are strict authorization boundaries. Commercial compliance platforms like Vanta, Drata, and Secureframe are SaaS products — they sit outside the boundary. To use them inside a FedRAMP environment, the tool itself would need FedRAMP authorization, creating a circular dependency.

OpenFRAMP solves this by running entirely inside your boundary. No external SaaS dependencies. No data leaves the environment.

## What OpenFRAMP Does

```
Pipeline 1: Infrastructure Scanning
──────────────────────────────────────────────────
Cloud Infrastructure    →  Steampipe SQL  →  Scanner Engine  →  OSCAL Assessment Results
(AWS, Azure, GitHub)       via catalogs      evaluation         (.json)

Pipeline 2: SSP Parsing
──────────────────────────────────────────────────
FedRAMP SSP Appendix A  →  Parser  →  OSCAL 1.1 SSP JSON
(.docx)                    323 controls extracted
```

- **Multi-cloud** — AWS, Azure/Entra ID, and GitHub from a single engine
- **Multi-framework** — FedRAMP Moderate, PCI DSS 4.0.1, and SOC 2 simultaneously
- **SSP Parser** — extracts 323 controls from FedRAMP SSP Appendix A Word documents and converts to OSCAL 1.1 JSON
- **Web Dashboard** — browser-based UI with scan trigger, provider tabs, and finding details at `localhost:4000`
- **Catalog-driven** — add checks by editing JSON, no code changes
- **OSCAL native** — generates Assessment Results in the format NIST mandates for FedRAMP
- **Docker deployment** — `docker compose up` and scan from your browser

## Current Coverage

**101 checks | 3 cloud providers | 3 compliance frameworks**

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

Checks include: S3 public access and encryption, IAM MFA enforcement, CloudTrail logging, security group rules, KMS key rotation and FIPS validation, GuardDuty, SecurityHub, password policies, EBS/RDS/DynamoDB encryption, VPC flow logs, and more.

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

Checks include: Storage account public access and encryption, TLS enforcement, Entra ID user status and MFA, conditional access policies, Key Vault soft delete and purge protection, NSG rules, Defender for Cloud, and more.

### GitHub (9 controls, 16 checks)

| Family | Controls |
| --- | --- |
| Access Control | AC-3, AC-6 |
| Audit & Accountability | AU-2 |
| Configuration Management | CM-2, CM-3, CM-7 |
| Risk Assessment | RA-5 |
| System Acquisition | SA-11 |
| System & Info Integrity | SI-7 |

Checks include: Branch protection (force push, deletions, PR reviews, status checks, signed commits), Dependabot vulnerability alerts, security policy presence, license, wiki settings, code owner reviews, and more.

### FedRAMP 20x KSI Coverage

OpenFRAMP maps checks to FedRAMP 20x Key Security Indicators. Current coverage: **23 of 61 Moderate KSIs** across all providers.

## Quick Start

### Option A: Docker Compose (recommended)

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
```

Create a `.env` file with your cloud credentials:

```
# Azure Service Principal (for Azure/Entra ID scanning)
AZURE_CLIENT_ID=your-app-id
AZURE_CLIENT_SECRET=your-secret
AZURE_TENANT_ID=your-tenant-id

# GitHub Personal Access Token (for GitHub scanning)
GITHUB_TOKEN=your-github-token
```

Build and start:

```bash
docker compose build
docker compose up -d
```

Open `http://localhost:4000` in your browser. Click **Run Scan**. That's it.

AWS credentials are mounted from `~/.aws` automatically.

### Option B: Run locally

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
./scan.sh                                        # scan all catalogs
./scan.sh catalog/fedramp-moderate-aws.json      # AWS only
./scan.sh catalog/fedramp-moderate-azure.json    # Azure only
./scan.sh catalog/github-security.json           # GitHub only
```

Prerequisites: [Steampipe](https://steampipe.io/) with AWS/Azure/GitHub plugins, Python 3.9+, cloud credentials configured.

See [INSTALL.md](INSTALL.md) for detailed setup instructions.

## Web Dashboard

The dashboard runs at `localhost:4000` and provides:

- **Provider tabs** — filter results by AWS, Azure, GitHub, or view all
- **Scan trigger** — click "Run Scan" to scan your infrastructure from the browser
- **Finding details** — click any control to see specific resources that passed or failed
- **Provider badges** — each finding shows which cloud provider it came from
- **SSP Upload** — parse FedRAMP SSP Appendix A documents and generate OSCAL SSP JSON
- **Progress tracking** — pass rate, compliance status, and control counts

## SSP Parser

OpenFRAMP includes a parser for FedRAMP SSP Appendix A Word documents. It extracts all 323 Moderate baseline controls including responsible roles, parameters, implementation status, control origination, and implementation narratives (parts a, b, c, etc.).

Upload through the web dashboard or run from the command line:

```bash
cd ssp-parser
python3 ssp_parser.py your-ssp-appendix-a.docx --output parsed.json
python3 ssp_to_oscal.py parsed.json --output oscal-ssp.json --name "Your System Name"
```

## Architecture

```
openframp/
├── catalog/
│   ├── fedramp-moderate-aws.json      ← AWS (31 controls, 57 checks)
│   ├── fedramp-moderate-azure.json    ← Azure + Entra ID (15 controls, 28 checks)
│   └── github-security.json           ← GitHub (9 controls, 16 checks)
├── oscal/
│   ├── scanner.py                     ← Generic scan engine (reads any catalog)
│   └── assessment-results-*.json      ← Generated OSCAL output per provider
├── ssp-parser/
│   ├── ssp_parser.py                  ← Extracts 323 controls from SSP docx
│   └── ssp_to_oscal.py               ← Converts to OSCAL 1.1 SSP JSON
├── web/
│   ├── app.py                         ← Flask API (scan trigger, results, SSP upload)
│   └── static/index.html             ← Dashboard UI
├── bootstrap/
│   ├── scanner-iam/                   ← AWS IAM User (OpenTofu)
│   └── scanner-role/                  ← AWS IAM Role with AssumeRole (OpenTofu)
├── scan.sh                            ← CLI entry point
├── Dockerfile                         ← Container image
└── docker-compose.yml                 ← One-command deployment
```

The scanner is **catalog-driven**. Adding a new check means adding a JSON entry — no code changes:

```json
{
  "check_id": "sc-28-ebs-encryption",
  "description": "EBS volumes should be encrypted",
  "severity": "high",
  "query": "select volume_id, encrypted from aws_ebs_volume"
}
```

New cloud provider = new catalog file, same engine. See [ARCHITECTURE.md](ARCHITECTURE.md) for design decisions.

## What V1 Does NOT Do

OpenFRAMP V1 is deliberately scoped. It does not:

- **Remediate findings** — V1 reports problems but does not fix them. A compliance scanner should never modify the environment it scans.
- **Replace a GRC platform** — no workflow management, ticket tracking, or vendor questionnaires. OpenFRAMP generates evidence; your GRC platform consumes it.
- **Cover non-technical controls** — physical security (PE), personnel security (PS), and other human-process controls cannot be automated.
- **Support FedRAMP High or Low** — V1 targets Moderate only.
- **Provide continuous monitoring** — V1 is run-on-demand. Scheduled scans via CI/CD are documented but not built in.
- **Support GCP** — V1 covers AWS, Azure, and GitHub. GCP requires a new catalog and Steampipe plugin.

## Security

- AWS scanning uses IAM Role with AssumeRole — temporary credentials that expire automatically
- Azure scanning uses a Service Principal with Reader + Directory.Read.All permissions
- GitHub scanning uses a Personal Access Token with `repo` and `read:org` scopes
- Credentials are never committed to the repository — `.env` is in `.gitignore`
- Branch protection, secret scanning, and Dependabot are enabled on this repository

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add checks, submit PRs, and contribute catalogs. The easiest contribution is adding a new check — it's a few lines of JSON.

## License

MIT

## Author

[Rupinder Pal Singh](https://github.com/RupinderSecurity) — Manager, Information Security | CISSP, CISM, CISA, CRISC
