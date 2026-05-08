# Architecture

This document explains how OpenFRAMP works, why it's built this way, and how the pieces fit together. It's intended for contributors, security engineers evaluating the tool, and anyone who wants to understand the design decisions.

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
Cloud           Steampipe          Scanner           OSCAL 1.1
Infrastructure  SQL queries   →    engine     →    Assessment
(AWS, Azure)    via catalogs       evaluation       Results JSON
```

Both pipelines produce standard OSCAL documents that can be viewed in the OSCAL Viewer or consumed by any OSCAL-compatible tool.

## Directory Structure

```
openframp/
├── catalog/                        # Control definitions (the "what to check")
│   ├── fedramp-moderate-aws.json   #   AWS: 31 controls, 57 checks
│   └── fedramp-moderate-azure.json #   Azure + Entra ID: 15 controls, 28 checks
│
├── oscal/                          # Scanner engine and output
│   ├── scanner.py                  #   Catalog-driven scan engine
│   ├── generate_ar.py              #   Legacy 6-check generator (still works)
│   └── assessment-results.json     #   Generated OSCAL Assessment Results
│
├── ssp-parser/                     # SSP document parsing
│   ├── ssp_parser.py               #   Extracts controls from SSP Appendix A docx
│   ├── ssp_to_oscal.py             #   Converts parsed data to OSCAL SSP JSON
│   └── (template docs)             #   FedRAMP SSP templates (not committed)
│
├── checks/                         # Legacy OPA/Rego policies
│   ├── s3_public_access.rego       #   Can still be used independently
│   ├── iam_mfa.rego                #   with: steampipe query | opa eval
│   └── ...                         #
│
├── bootstrap/                      # Infrastructure as code for scanner setup
│   ├── scanner-iam/                #   IAM User with SecurityAudit (static creds)
│   └── scanner-role/               #   IAM Role with AssumeRole (temp creds)
│
├── lab-environment/                # Test resources for development
│   └── main.tf                     #   Creates secure + insecure S3 buckets
│
├── scan.sh                         # Entry point script
├── Dockerfile                      # Containerized deployment
└── INSTALL.md                      # Installation guide
```

## Design Decisions

### Why catalog-driven instead of individual policy files?

The first version of OpenFRAMP used individual OPA/Rego files — one per check. Each file contained a Steampipe SQL query and a Rego policy that evaluated the results. This approach is auditable (each policy is a standalone artifact) but does not scale. Going from 6 checks to 80 would require 80 separate files, each with its own query, policy logic, and test.

The catalog approach stores check definitions as JSON data. Adding a new check means adding a few lines to a catalog file — no code changes to the scanner engine. This reduced the effort to add a check from "write three files and update the generator" to "add four lines of JSON."

The tradeoff: catalog-driven evaluation logic lives in Python pattern matching rather than declarative Rego policies. This is less formally auditable than Rego. The planned future architecture combines both — catalogs define what to check, Rego files define how to evaluate for the most critical controls where formal policy-as-code matters.

### Why Steampipe?

Steampipe was chosen over alternatives for several reasons:

**vs. Prowler:** Prowler runs predefined checks against predefined benchmarks. You cannot easily add custom checks or query arbitrary resource properties. Steampipe exposes every cloud resource as a SQL table, allowing arbitrary queries. OpenFRAMP uses this to map checks to any compliance framework, not just CIS Benchmarks.

**vs. Cloud Custodian:** Cloud Custodian is primarily a policy enforcement engine (it takes actions like shutting down non-compliant resources). OpenFRAMP is read-only by design. A compliance scanner that modifies the environment it scans is a non-starter for FedRAMP assessors.

**vs. AWS Config Rules / Azure Policy:** These are cloud-native but vendor-locked. OpenFRAMP scans AWS and Azure from the same engine. Adding GCP requires installing one Steampipe plugin, not adopting an entirely different policy framework.

**vs. Custom API calls:** Steampipe handles pagination, rate limiting, credential management, and caching. Writing raw boto3 or Azure SDK calls for 85 checks would be thousands of lines of infrastructure code that Steampipe eliminates.

### Why run inside the boundary?

FedRAMP authorization boundaries define what systems can access what data. SaaS compliance tools (Vanta, Drata, Secureframe) operate outside the boundary. For them to scan inside a FedRAMP Government Cloud environment, the tool itself would need FedRAMP authorization — creating a circular dependency.

OpenFRAMP runs as a container or local process inside the boundary. It uses the same IAM roles and network paths as other authorized systems. No data crosses the boundary. No external SaaS dependency. This is architecturally equivalent to running Nessus inside your network instead of using a cloud-hosted vulnerability scanner.

### Why OSCAL?

NIST's Open Security Controls Assessment Language (OSCAL) is becoming the mandatory format for FedRAMP compliance evidence. The September 2026 deadline means every FedRAMP-authorized system needs OSCAL-formatted packages. By generating OSCAL natively, OpenFRAMP produces evidence that feeds directly into the authorization process without format conversion.

OSCAL also enables machine-readable compliance data. Instead of auditors reading PDF narratives, they can programmatically validate that controls are implemented, compare assessment results across time periods, and identify gaps automatically. This is the foundation for continuous compliance rather than point-in-time assessment.

### Why IAM Role over IAM User?

The bootstrap module provides two options: an IAM User with static access keys, and an IAM Role with AssumeRole for temporary credentials. The role-based approach is recommended because:

- Temporary credentials expire automatically (1 hour default). No long-lived secrets to rotate or leak.
- The scanner user's static key is only used to call `sts:AssumeRole`, not to access any AWS services directly.
- The state file (`terraform.tfstate`) for the role module contains no secrets — the role ARN is not sensitive.
- This pattern matches how production FedRAMP environments manage service accounts.

The IAM User option exists for quick local testing where the additional complexity of role assumption is not justified.

## Catalog Schema

Each catalog file is a JSON document with this structure:

```json
{
  "catalog_version": "2.0.0",
  "framework": "Multi-Framework",
  "baseline": "FedRAMP Moderate + PCI DSS 4.0.1 + SOC 2",
  "provider": "aws",
  "controls": [
    {
      "control_id": "AC-2",
      "title": "Account Management",
      "family": "Access Control",
      "frameworks": ["FedRAMP AC-2", "PCI DSS 8.1", "SOC 2 CC6.1"],
      "checks": [
        {
          "check_id": "ac-2-no-root-access-keys",
          "description": "Root account should not have access keys",
          "severity": "critical",
          "query": "select account_access_keys_present from aws_iam_account_summary",
          "resource_type": "aws_iam_account_summary"
        }
      ]
    }
  ]
}
```

**Fields:**

- `control_id`: NIST 800-53 Rev 5 control identifier
- `frameworks`: Array of framework-specific control references this check satisfies
- `checks`: Array of individual checks for this control. Each check has a unique `check_id`, human-readable `description`, `severity` (critical/high/medium/low), the `query` to run via Steampipe, and the `resource_type` being checked
- `provider`: Which cloud provider this catalog targets (aws, azure)

Adding a new check requires only adding a JSON entry to the appropriate catalog file. The scanner engine processes it automatically.

## Scanner Engine

`oscal/scanner.py` is the core engine. It:

1. Loads a catalog JSON file
2. For each control, runs each check's SQL query via Steampipe
3. Evaluates the query results against known patterns (encryption missing, MFA disabled, public access enabled, etc.)
4. Collects pass/fail findings with control mappings and severity
5. Generates an OSCAL Assessment Results document

The evaluation logic uses pattern matching on check IDs to determine pass/fail criteria. For example, any check with "mfa" in its ID evaluates the `mfa_enabled` field. Any check with "encryption" evaluates encryption configuration fields.

Error handling distinguishes between:
- **Service not enabled** (e.g., GuardDuty not activated): reported as a finding ("service not enabled in this account")
- **Service not available** (e.g., Redshift in Free Tier): reported as a finding
- **Query errors** (e.g., wrong column names): reported as errors and counted separately

## SSP Parser

The SSP parser handles FedRAMP SSP Appendix A documents, which contain 323 Moderate baseline controls in a structured Word document format. Each control has two tables:

1. **Summary table**: Contains the control ID, responsible role, parameters, implementation status, and control origination
2. **Implementation table**: Contains parts (a, b, c, etc.) with narrative descriptions of how the control is implemented

The parser extracts both tables for each control and produces structured JSON. The OSCAL SSP generator then converts this JSON to a valid OSCAL 1.1 System Security Plan document with proper `implemented-requirements`, `statements`, and `set-parameters`.

## What V1 Deliberately Does NOT Do

- **Multi-tenant deployment**: V1 is single-user, single-scan. No user management, no shared state.
- **Continuous monitoring**: V1 is run-once, produce-report. Scheduled scans via CI/CD are documented but not built in.
- **Remediation automation**: V1 reports findings. It does not fix them. A compliance scanner should never modify the environment it scans.
- **GCP support**: V1 covers AWS and Azure. GCP requires a new catalog and Steampipe plugin configuration.
- **FedRAMP High or Low baselines**: V1 targets Moderate only. High adds approximately 100 additional controls. Low is a subset.
- **Non-cloud controls**: Physical security (PE family), personnel security (PS family), and other non-technical controls cannot be automated and are excluded.
- **POA&M generation**: V1 produces Assessment Results but does not generate Plans of Action and Milestones from findings.
