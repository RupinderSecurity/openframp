# OpenFRAMP

Open-source FedRAMP compliance pipeline that runs inside authorization boundaries where SaaS scanners cannot operate.

## The Problem

FedRAMP Government Cloud environments are strict authorization boundaries. Commercial compliance platforms like Vanta, Drata, and Secureframe are SaaS products — they sit outside the boundary. To use them inside a FedRAMP environment, the tool itself would need FedRAMP authorization, creating a circular dependency. Most organizations resort to manual evidence collection: screenshots, spreadsheets, and point-in-time assessments.

## What OpenFRAMP Does

OpenFRAMP is a self-contained compliance pipeline that runs entirely inside your boundary. No external SaaS dependencies. No data leaves the environment.

```
Steampipe (data collection)
    → OPA (policy evaluation)
        → OSCAL Assessment Results (standardized output)
```

- **Scans** cloud infrastructure using Steampipe SQL queries
- **Evaluates** findings against OPA/Rego compliance policies mapped to specific controls (FedRAMP, PCI DSS, SOC 2)
- **Generates** OSCAL-formatted Assessment Results — the format NIST is mandating for FedRAMP by September 2026

## Current State

Pre-alpha. Core pipeline is functional:

- `bootstrap/scanner-iam/` — OpenTofu module that provisions a read-only IAM scanner user with the AWS-managed SecurityAudit policy
- `lab-environment/` — OpenTofu module that creates intentionally compliant and non-compliant S3 buckets for testing
- `checks/` — Steampipe queries and OPA/Rego policies for S3 public access controls (FedRAMP AC-3, PCI DSS 1.3)
- `oscal/` — Python script that runs the full pipeline and generates OSCAL Assessment Results JSON

## Quick Start

### Prerequisites

- [OpenTofu](https://opentofu.org/) or Terraform
- [Steampipe](https://steampipe.io/) with the AWS plugin
- [OPA](https://www.openpolicyagent.org/)
- Python 3.9+
- AWS account with credentials configured

### Bootstrap the scanner

```bash
cd bootstrap/scanner-iam
tofu init && tofu apply
```

This creates a read-only IAM user with the SecurityAudit policy attached. Configure the output credentials in `~/.aws/credentials`.

### Run the pipeline

```bash
python3 oscal/generate_ar.py
```

This runs Steampipe → OPA → OSCAL generation in one command. Output is written to `oscal/assessment-results.json`.

### Run individual checks

```bash
# Scan S3 buckets and evaluate with OPA
steampipe query --output json \
  "select name, block_public_acls, block_public_policy, restrict_public_buckets, ignore_public_acls from aws_s3_bucket" \
  | opa eval -i /dev/stdin -d checks/s3_public_access.rego "data.openframp.s3"
```

## Roadmap

- [ ] Additional control families (IA-2, AU-2, SC-28, SC-12, SC-13)
- [ ] Prowler integration for CIS Benchmark checks
- [ ] OSCAL SSP (System Security Plan) parser
- [ ] OSCAL Viewer — React dashboard for navigating assessment results
- [ ] Containerized deployment (Docker) for single-command scanning
- [ ] Multi-cloud support (Azure, GCP)
- [ ] CI/CD integration for scheduled compliance scans

## Why OSCAL Matters

NIST's OSCAL (Open Security Controls Assessment Language) is becoming the mandatory format for FedRAMP compliance evidence. The September 2026 deadline means every FedRAMP-authorized system needs OSCAL-formatted packages. Most organizations don't have tooling for this yet. OpenFRAMP generates OSCAL Assessment Results natively.

## License

MIT

## Author

[Rupinder Pal Singh](https://github.com/RupinderSecurity) — Manager, Information Security
