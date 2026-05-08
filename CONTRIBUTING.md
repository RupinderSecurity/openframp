# Contributing to OpenFRAMP

Thank you for your interest in contributing. OpenFRAMP is an open-source project and welcomes contributions of all kinds — new checks, bug fixes, documentation improvements, and catalog expansions.

## Ways to Contribute

### Add a new compliance check (easiest)

This is the most impactful contribution and requires no Python knowledge. Each check is a JSON entry in a catalog file.

1. Open the appropriate catalog file in `catalog/`:
   - `fedramp-moderate-aws.json` for AWS checks
   - `fedramp-moderate-azure.json` for Azure/Entra ID checks

2. Find the control family your check belongs to (e.g., AC for Access Control, SC for System Protection)

3. Add a new entry to the `checks` array:

```json
{
  "check_id": "sc-28-ebs-snapshot-encryption",
  "description": "EBS snapshots should be encrypted",
  "severity": "high",
  "query": "select snapshot_id, encrypted from aws_ebs_snapshot where encrypted = false",
  "resource_type": "aws_ebs_snapshot"
}
```

4. Test your check locally:

```bash
steampipe query "YOUR_QUERY_HERE"
```

5. Run the full scanner to verify nothing breaks:

```bash
./scan.sh catalog/fedramp-moderate-aws.json
```

6. Submit a pull request

**Finding the right Steampipe query:** Browse the Steampipe Hub at https://hub.steampipe.io to find available tables and columns for AWS, Azure, and other plugins.

### Add a new cloud provider catalog

1. Create a new catalog file: `catalog/fedramp-moderate-PROVIDER.json`
2. Install the corresponding Steampipe plugin: `steampipe plugin install PROVIDER`
3. Follow the existing catalog schema (see `ARCHITECTURE.md` for the full schema)
4. Test each query individually before adding it to the catalog
5. Submit a pull request

### Report a bug

Use the [Bug Report template](https://github.com/RupinderSecurity/openframp/issues/new?template=bug_report.md) and include:

- What happened
- What you expected
- Steps to reproduce
- Your environment (OS, Docker version, cloud provider)

### Suggest a feature

Use the [Feature Request template](https://github.com/RupinderSecurity/openframp/issues/new?template=feature_request.md) and include:

- What you'd like
- Which framework and cloud provider it relates to
- Why it matters for compliance

### Improve documentation

Documentation fixes and improvements are always welcome. This includes README, INSTALL.md, ARCHITECTURE.md, and inline code comments.

## Development Setup

1. Fork and clone the repo:

```bash
git clone git@github.com:YOUR_USERNAME/openframp.git
cd openframp
```

2. Install dependencies:

```bash
brew install steampipe
steampipe plugin install aws
steampipe plugin install azure
steampipe plugin install azuread
pip3 install python-docx
```

3. Configure cloud credentials (see INSTALL.md)

4. Run the scanner to verify your setup:

```bash
./scan.sh
```

## Pull Request Process

1. Create a feature branch from `main`:

```bash
git checkout -b feature/add-lambda-checks
```

2. Make your changes. Keep commits focused — one logical change per commit.

3. Test your changes:

```bash
# Run the scanner
./scan.sh

# If you modified the SSP parser
cd ssp-parser
python3 ssp_parser.py SSP-Appendix-A-Moderate-FedRAMP-Security-Controls.docx
```

4. Commit with a descriptive message:

```bash
git commit -m "catalog: add Lambda function checks for CM-2 and SC-28"
```

5. Push and open a pull request:

```bash
git push origin feature/add-lambda-checks
```

6. In the PR description, explain what you changed and why. If adding checks, list the control IDs and frameworks covered.

## Commit Message Format

Use this format:

```
area: short description

Longer explanation if needed.
```

Areas: `catalog`, `scanner`, `ssp-parser`, `bootstrap`, `docs`, `docker`, `fix`

Examples:
- `catalog: add ECS and EKS checks for CM-2 and SC-28`
- `scanner: handle AccessDenied errors as findings`
- `fix: correct column name for aws_vpc flow logs`
- `docs: add Azure CLI troubleshooting to INSTALL.md`

## Code of Conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be respectful, constructive, and professional.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Open an issue or reach out to the maintainer at rupinderpalsing@proton.me.
