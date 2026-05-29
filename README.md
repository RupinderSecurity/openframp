# OpenFRAMP

Open-source multi-framework, multi-cloud compliance scanner that runs inside authorization boundaries where SaaS tools cannot operate.

## The Problem

FedRAMP Government Cloud environments are strict authorization boundaries. Commercial compliance platforms like Vanta, Drata, and Secureframe are SaaS products. They sit outside the boundary. To use them inside a FedRAMP environment, the tool itself would need FedRAMP authorization, creating a circular dependency. Most organizations resort to manual evidence collection: screenshots, spreadsheets, and point-in-time assessments.

## What OpenFRAMP Does

OpenFRAMP is a self-contained compliance pipeline that runs entirely inside your boundary. No external SaaS dependencies. No data leaves the environment.

    Catalog (JSON control definitions per cloud provider)
        -> Steampipe (cloud data collection via SQL)
            -> Policy evaluation
                -> OSCAL Assessment Results (standardized output)

- **Multi-cloud**: AWS and Azure/Entra ID from a single engine, with a GitHub security catalog in progress
- **Multi-framework**: FedRAMP Moderate, PCI DSS 4.0.1, and SOC 2 mapped per check
- **Catalog-driven**: add checks by editing JSON, no code changes
- **OSCAL native**: generates Assessment Results in OSCAL, the format FedRAMP requires for authorization packages under RFC-0024 (new packages due in machine-readable OSCAL by September 30, 2026)
- **Runs anywhere**: locally, in Docker, or inside your authorization boundary

## Coverage

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

### GitHub (in progress)

A `catalog/github-security.json` catalog exists and the engine handles GitHub data including Dependabot. [confirm: state coverage numbers or mark as early/experimental.]

Every check maps to **FedRAMP Moderate**, **PCI DSS 4.0.1**, and **SOC 2**. The mapping rationale lives in the catalog entries. If you are evaluating the mappings, start there. [confirm: this is the spot reviewers will scrutinize, so make sure each mapping is defensible.]

## Two ways it evaluates

OpenFRAMP has two evaluation paths. [confirm which one you want to present as canonical, and label the other as alternate or legacy so readers are not confused.]

- **Catalog engine (`oscal/scanner.py`)**: reads any JSON catalog, runs the Steampipe queries, evaluates inline, and emits OSCAL Assessment Results. This is the path the Quick Start uses.
- **Policy engine (`oscal/generate_ar.py` + `checks/*.rego`)**: runs Steampipe queries and evaluates results with Open Policy Agent (Rego) before emitting OSCAL. Use this if you prefer policy-as-code in Rego.

## Quick Start

### Run with Docker (recommended, no local dependencies)

    docker build -t openframp .
    docker run --rm -v ~/.aws:/home/scanner/.aws:ro openframp

The web viewer runs via Docker Compose on port 4000:

    docker compose up

### Run locally

    git clone https://github.com/RupinderSecurity/openframp.git
    cd openframp
    ./scan.sh                                        # scan all catalogs
    ./scan.sh catalog/fedramp-moderate-aws.json      # AWS only
    ./scan.sh catalog/fedramp-moderate-azure.json    # Azure only

### Prerequisites (local runs)

- [Steampipe](https://steampipe.io/) with the AWS and/or Azure plugins
- [Open Policy Agent (opa)](https://www.openpolicyagent.org/) on your PATH (`scan.sh` checks for it)
- Python 3.9+
- Cloud credentials configured (AWS CLI and/or Azure CLI)

## Architecture

High-level layout:

    openframp/
    ├── catalog/        JSON control definitions (AWS, Azure, GitHub)
    ├── oscal/          scanner.py (catalog engine), generate_ar.py (OPA engine), OSCAL output
    ├── checks/         Rego policies used by the OPA engine
    ├── ssp-parser/     SSP docx to OSCAL SSP parser, with tests
    ├── web/            OSCAL viewer (Flask app + static dashboard)
    ├── bootstrap/      OpenTofu for scanner IAM user and AssumeRole
    ├── scan.sh         entry point
    └── Dockerfile      containerized deployment

Full detail is in [ARCHITECTURE.md](ARCHITECTURE.md).

### Catalog-driven design

Adding a new check means adding JSON, no code changes:

    {
      "check_id": "sc-28-s3-encryption",
      "description": "S3 buckets should have encryption enabled",
      "severity": "high",
      "query": "select name, server_side_encryption_configuration from aws_s3_bucket"
    }

New cloud provider means a new catalog file and the same engine.

## Status

### Working now

- AWS: 31 controls, 57 checks, 9 control families
- Azure + Entra ID: 15 controls, 28 checks
- Multi-framework mapping (FedRAMP Moderate, PCI DSS 4.0.1, SOC 2)
- Catalog engine and Rego/OPA engine, both emitting OSCAL Assessment Results
- SSP docx to OSCAL SSP parser (`ssp-parser/`, with tests)
- OSCAL viewer (`web/`)
- IAM Role with AssumeRole, no long-lived secrets
- Docker and Docker Compose

### In progress / planned

- GitHub/GitLab security catalog (GitHub catalog started)
- Expand Azure catalog to match AWS depth
- GCP catalog
- Remediation guidance per finding
- CI/CD with OIDC for scheduled scans

[confirm the split above against where each piece actually is. Move anything that is rough from "Working now" to "In progress."]

## Contributing

Contributions are welcome, and the easiest one needs no Python: add a compliance check by adding a JSON entry to a catalog file in `catalog/`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide, issue templates, and PR process.

## Security

OpenFRAMP is designed so no data leaves your boundary. To report a security issue, see [SECURITY.md](SECURITY.md). Do not commit real scan output, account identifiers, or environment data to the repo.

## License

MIT. See [LICENSE](LICENSE).

## Author

[Rupinder Pal Singh](https://github.com/RupinderSecurity), Manager, Information Security.
