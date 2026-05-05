# Installing and Running OpenFRAMP

## Quick Start (5 minutes)

### Option A: Docker (recommended — no dependencies)

1. Clone the repo:

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
```

2. Build the container:

```bash
docker build -t openframp .
```

3. Run a scan (AWS):

```bash
docker run --rm -v ~/.aws:/home/scanner/.aws:ro openframp
```

That's it. Results are printed to the terminal and written to `oscal/assessment-results.json` inside the container. To save results locally:

```bash
docker run --rm \
  -v ~/.aws:/home/scanner/.aws:ro \
  -v $(pwd)/output:/home/scanner/openframp/oscal \
  openframp
```

Results will be in `./output/assessment-results.json`.

### Option B: Run locally

#### Prerequisites

- **Python 3.9+** — check with `python3 --version`
- **Steampipe** — install from https://steampipe.io
- **OPA** (optional, for legacy rego checks) — install from https://www.openpolicyagent.org

#### Install Steampipe plugins

For AWS scanning:

```bash
steampipe plugin install aws
```

For Azure + Entra ID scanning:

```bash
steampipe plugin install azure
steampipe plugin install azuread
```

#### Configure cloud credentials

**AWS:** Configure the AWS CLI with credentials that have the `SecurityAudit` managed policy attached:

```bash
aws configure
```

Or use the included OpenTofu module to create a dedicated read-only scanner:

```bash
cd bootstrap/scanner-role
tofu init && tofu apply
```

This creates an IAM Role with `SecurityAudit` policy. Configure Steampipe to use it by adding to `~/.aws/config`:

```ini
[profile openframp-scanner]
role_arn = arn:aws:iam::YOUR_ACCOUNT_ID:role/openframp-scanner-role
source_profile = default
region = us-west-2
```

And adding to `~/.steampipe/config/aws.spc`:

```hcl
connection "aws" {
  plugin  = "aws"
  profile = "openframp-scanner"
  regions = ["us-west-2"]
}
```

**Azure:** Sign in with the Azure CLI:

```bash
az login
```

Steampipe picks up Azure CLI credentials automatically. Create the config files.

`~/.steampipe/config/azure.spc`:

```hcl
connection "azure" {
  plugin = "azure"
}
```

`~/.steampipe/config/azuread.spc`:

```hcl
connection "azuread" {
  plugin = "azuread"
}
```

#### Run the scan

```bash
cd openframp
./scan.sh                                        # scan all catalogs
./scan.sh catalog/fedramp-moderate-aws.json      # AWS only
./scan.sh catalog/fedramp-moderate-azure.json    # Azure only
```

Results are written to `oscal/assessment-results.json`.

## What gets scanned

OpenFRAMP scans your cloud environment against 85 checks across 46 controls covering FedRAMP Moderate, PCI DSS 4.0.1, and SOC 2.

**AWS checks include:** S3 public access and encryption, IAM MFA enforcement, CloudTrail logging, security group rules, KMS key rotation, GuardDuty, SecurityHub, password policies, EBS encryption, RDS encryption and backups, and more.

**Azure checks include:** Storage account public access and encryption, Entra ID user status and MFA, Key Vault configuration, network security groups, TLS enforcement, Defender for Cloud, and more.

The scanner uses read-only access. It never modifies your environment.

## Understanding the output

The scanner prints a summary to the terminal:

```
  [AC-2] Account Management
    ✓ ac-2-iam-user-activity: 1 passed
    ✓ ac-2-no-root-access-keys: 1 passed
  [IA-2] Identification and Authentication
    ✗ ia-2-iam-user-mfa: 1 failed
```

- ✓ = check passed (resource is compliant)
- ✗ = check failed (finding — needs remediation)
- ⚠ = query error (usually a permission or service issue)
- — = no resources found (nothing to check)

The full results are written to `oscal/assessment-results.json` in OSCAL Assessment Results format.

## Troubleshooting

**"Cannot connect to AWS"** — Run `aws sts get-caller-identity` to verify your credentials work. The scanner needs the `SecurityAudit` managed policy at minimum.

**"SubscriptionRequiredException" or "OptInRequired"** — The AWS service (GuardDuty, SecurityHub, etc.) is not enabled in your account. This is reported as a finding, not an error. The scanner handles this automatically.

**"Unable to parse config file"** — Your `~/.aws/credentials` file has a formatting issue. Run `cat ~/.aws/credentials` and check for extra spaces, blank lines inside a section, or missing values.

**Steampipe plugin errors** — Run `steampipe plugin update --all` to ensure plugins are current.

**Azure "authorization failed"** — Run `az login` to refresh your token. Azure CLI tokens expire after a few hours.

**Docker build fails** — Make sure Docker Desktop is running. On Mac, open Docker from Applications.

## Permissions required

**AWS:** The `SecurityAudit` AWS-managed policy provides read-only access to all services the scanner checks. No write permissions are needed. For the IAM Role approach, the scanner user also needs `sts:AssumeRole` on the scanner role.

**Azure:** The default Reader role on the subscription plus Directory Reader on Entra ID. The Azure CLI login typically provides sufficient access for a free or personal account.
