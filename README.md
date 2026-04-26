# OpenFRAMP

Open-source multi-framework compliance scanner that runs inside authorization boundaries where SaaS tools cannot operate.

## The Problem

FedRAMP Government Cloud environments are strict authorization boundaries. Commercial compliance platforms like Vanta, Drata, and Secureframe are SaaS products — they sit outside the boundary. To use them inside a FedRAMP environment, the tool itself would need FedRAMP authorization, creating a circular dependency. Most organizations resort to manual evidence collection: screenshots, spreadsheets, and point-in-time assessments.

## What OpenFRAMP Does

OpenFRAMP is a self-contained compliance pipeline that runs entirely inside your boundary. No external SaaS dependencies. No data leaves the environment.

```
Catalog (JSON control definitions)
    → Steampipe (cloud data collection via SQL)
        → Scanner engine (policy evaluation)
            → OSCAL Assessment Results (standardized output)
```

- **Scans** cloud infrastructure using Steampipe SQL queries
- **Evaluates** findings against compliance policies mapped to specific controls
- **Covers three frameworks simultaneously** — FedRAMP Moderate, PCI DSS 4.0.1, and SOC 2
- **Generates** OSCAL-formatted Assessment Results — the format NIST is mandating for FedRAMP by September 2026
- **Runs anywhere** — locally, in Docker, or inside your authorization boundary

## Current Coverage

**31 controls | 57 individual checks | 9 control families | 3 frameworks**

| Family | Controls | Frameworks |
| --- | --- | --- |
| Access Control | AC-2, AC-3, AC-4, AC-6, AC-7, AC-17 | FedRAMP, PCI DSS, SOC 2 |
| Audit & Accountability | AU-2, AU-3, AU-6, AU-9, AU-11 | FedRAMP, PCI DSS, SOC 2 |
| Configuration Management | CM-2, CM-6, CM-7, CM-8 | FedRAMP, PCI DSS, SOC 2 |
| Contingency Planning | CP-9, CP-10 | FedRAMP, SOC 2 |
| Identification & Auth | IA-2, IA-5 | FedRAMP, PCI DSS, SOC 2 |
| Incident Response | IR-6 | FedRAMP, PCI DSS, SOC 2 |
| Risk Assessment | RA-5 | FedRAMP, PCI DSS, SOC 2 |
| System & Comm Protection | SC-7, SC-8, SC-12, SC-13, SC-23, SC-28 | FedRAMP, PCI DSS, SOC 2 |
| System & Info Integrity | SI-2, SI-3, SI-4, SI-7 | FedRAMP, PCI DSS, SOC 2 |

## Quick Start

### Prerequisites

- AWS account with credentials configured
- [Steampipe](https://steampipe.io/) with the AWS plugin (for local runs)
- Python 3.9+
- OR just Docker (no other dependencies needed)

### Run with Docker (recommended)

```bash
docker build -t openframp .
docker run --rm -v ~/.aws:/home/scanner/.aws:ro openframp
```

That's it. One command. No dependencies to install.

### Run locally

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
./scan.sh
```

### Bootstrap a read-only scanner (optional)

For production use, create a dedicated scanner with least-privilege access:

```bash
# Option A: IAM Role with temporary credentials (recommended)
cd bootstrap/scanner-role
tofu init && tofu apply

# Option B: IAM User with static credentials
cd bootstrap/scanner-iam
tofu init && tofu apply
```

The role-based approach uses AssumeRole for temporary credentials that expire automatically. No long-lived secrets in the pipeline.

## Architecture

```
openframp/
├── catalog/
│   └── fedramp-moderate-aws.json    ← Control definitions (add checks here)
├── checks/                          ← Legacy OPA/Rego policies (still usable)
├── oscal/
│   ├── scanner.py                   ← Generic scan engine
│   └── assessment-results.json      ← Generated OSCAL output
├── bootstrap/
│   ├── scanner-iam/                 ← IAM User module (OpenTofu)
│   └── scanner-role/                ← IAM Role module (OpenTofu)
├── lab-environment/                 ← Test resources (secure + insecure)
├── scan.sh                          ← Entry point
└── Dockerfile                       ← Containerized deployment
```

### How it works

The scanner is **catalog-driven**. Adding a new check means adding a JSON entry to the catalog file — no code changes required. Each catalog entry defines: a control ID, description, severity, the Steampipe SQL query to run, and which frameworks it maps to.

```json
{
  "control_id": "SC-28",
  "title": "Protection of Information at Rest",
  "frameworks": ["FedRAMP SC-28", "PCI DSS 3.5.2", "SOC 2 CC6.1"],
  "checks": [
    {
      "check_id": "sc-28-s3-encryption",
      "description": "S3 buckets should have server-side encryption enabled",
      "severity": "high",
      "query": "select name, server_side_encryption_configuration from aws_s3_bucket"
    }
  ]
}
```

One scan produces findings mapped to all three frameworks simultaneously.

## Sample Output

```
============================================================
OpenFRAMP — Multi-Framework Scanner
Provider: AWS | Baseline: FedRAMP Moderate + PCI DSS 4.0.1 + SOC 2
============================================================

  [AC-2] Account Management
    ✓ ac-2-iam-user-activity: 1 passed
    ✓ ac-2-no-root-access-keys: 1 passed
  [IA-2] Identification and Authentication
    ✗ ia-2-iam-user-mfa: 1 failed
    ✓ ia-2-root-mfa: 1 passed
  [SC-28] Protection of Information at Rest
    ✓ sc-28-s3-encryption: 2 passed

============================================================
Controls scanned: 31
Individual checks: 57
Results: 14 passed, 17 failed
OSCAL output: oscal/assessment-results.json
============================================================
```

## Roadmap

### Completed
- [x] AC-2, AC-3, AC-4, AC-6, AC-7, AC-17 (Access Control family)
- [x] AU-2, AU-3, AU-6, AU-9, AU-11 (Audit family)
- [x] CM-2, CM-6, CM-7, CM-8 (Configuration Management)
- [x] CP-9, CP-10 (Contingency Planning)
- [x] IA-2, IA-5 (Identification and Authentication)
- [x] SC-7, SC-8, SC-12, SC-13, SC-23, SC-28 (System Protection)
- [x] SI-2, SI-3, SI-4, SI-7 (System Integrity)
- [x] IR-6, RA-5 (Incident Response, Risk Assessment)
- [x] Multi-framework mapping (FedRAMP + PCI DSS + SOC 2)
- [x] IAM Role with AssumeRole (no long-lived secrets)
- [x] Docker container for single-command deployment
- [x] OSCAL Assessment Results generation

### In Progress
- [ ] Expand to 80+ automatable FedRAMP Moderate controls
- [ ] Azure and Entra ID catalog
- [ ] OSCAL Viewer dashboard (React)
- [ ] CI/CD integration with OIDC for scheduled scans

### Planned
- [ ] OSCAL SSP (System Security Plan) parser
- [ ] Multi-cloud support (Azure, GCP)
- [ ] Remediation guidance per finding
- [ ] Remote encrypted state backend
- [ ] Contributing guide and community catalog submissions

## Why OSCAL Matters

NIST's OSCAL (Open Security Controls Assessment Language) is becoming the mandatory format for FedRAMP compliance evidence. The September 2026 deadline means every FedRAMP-authorized system needs OSCAL-formatted packages. Most organizations don't have tooling for this yet. OpenFRAMP generates OSCAL Assessment Results natively.

## License

MIT

## Author

[Rupinder Pal Singh](https://github.com/RupinderSecurity) — Manager, Information Security
