# Installing and Running OpenFRAMP

## Quick Start (5 minutes)

### Option A: Docker Compose (recommended)

```bash
git clone https://github.com/RupinderSecurity/openframp.git
cd openframp
```

Create a `.env` file with your cloud credentials:

```bash
cat > .env <<'EOF'
AZURE_CLIENT_ID=your-app-id
AZURE_CLIENT_SECRET=your-secret
AZURE_TENANT_ID=your-tenant-id
GITHUB_TOKEN=your-github-token
EOF
```

Build and start:

```bash
docker compose build
docker compose up -d
```

Open `http://localhost:4000` in your browser. Click "Run Scan" to scan your cloud environment.

### Option B: Run locally

#### Prerequisites

- Python 3.9+
- [Steampipe](https://steampipe.io/)
- Cloud credentials configured

#### Install Steampipe plugins

```bash
steampipe plugin install aws        # For AWS scanning
steampipe plugin install azure      # For Azure scanning
steampipe plugin install azuread    # For Entra ID scanning
steampipe plugin install github     # For GitHub scanning
```

#### Configure cloud credentials

**AWS:** Configure credentials with the `SecurityAudit` managed policy:

```bash
aws configure
```

For production use, create a dedicated scanner role:

```bash
cd bootstrap/scanner-role
tofu init && tofu apply
```

Add to `~/.aws/config`:

```ini
[profile openframp-scanner]
role_arn = arn:aws:iam::YOUR_ACCOUNT_ID:role/openframp-scanner-role
source_profile = default
region = us-west-2
```

Add to `~/.steampipe/config/aws.spc`:

```hcl
connection "aws" {
  plugin  = "aws"
  profile = "openframp-scanner"
  regions = ["us-west-2"]
}
```

**Azure:** For local scanning, sign in with Azure CLI:

```bash
az login
```

For Docker, create a service principal:

```bash
az ad sp create-for-rbac --name "openframp-scanner" --role "Reader" \
  --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID"
```

Then grant Entra ID permissions in Azure Portal:

1. Go to App registrations → openframp-scanner → API permissions
2. Add permission → Microsoft Graph → Application permissions
3. Add `User.Read.All` and `Directory.Read.All`
4. Click "Grant admin consent for Default Directory"

Add the credentials to `.env` for Docker use.

For local use, create Steampipe configs:

```hcl
# ~/.steampipe/config/azure.spc
connection "azure" {
  plugin = "azure"
}

# ~/.steampipe/config/azuread.spc
connection "azuread" {
  plugin = "azuread"
}
```

**GitHub:** Create a personal access token at https://github.com/settings/tokens (classic) with scopes: `repo`, `read:org`, `admin:repo_hook`.

For local use:

```hcl
# ~/.steampipe/config/github.spc
connection "github" {
  plugin = "github"
  token  = "ghp_your_token_here"
}
```

For Docker, add `GITHUB_TOKEN=ghp_your_token_here` to `.env`.

#### Run the scan

```bash
./scan.sh                                        # scan all providers
./scan.sh catalog/fedramp-moderate-aws.json      # AWS only
./scan.sh catalog/fedramp-moderate-azure.json    # Azure only
./scan.sh catalog/github-security.json           # GitHub only
```

#### Start the web dashboard

```bash
cd web
python3 app.py
```

Open `http://localhost:4000`.

## Web Dashboard

The dashboard at `localhost:4000` provides:

- **Provider tabs** — filter by AWS, Azure & Entra ID, or GitHub
- **Run Scan** — trigger a live scan from the browser
- **Upload SSP** — parse FedRAMP SSP Appendix A (.docx) into OSCAL SSP JSON
- **Expandable controls** — click to see findings with resource names and severity
- **Progress bar** — compliance posture at a glance

## SSP Parsing

Parse FedRAMP SSP Appendix A documents and generate OSCAL 1.1 SSP JSON.

**Web dashboard:** Click "Upload SSP" and select your `.docx` file.

**Command line:**

```bash
cd ssp-parser
python3 ssp_parser.py path/to/SSP-Appendix-A.docx --output parsed.json
python3 ssp_to_oscal.py parsed.json --output oscal-ssp.json --name "My System"
```

## Coverage

**101 checks across 3 providers and 3 compliance frameworks:**

| Provider | Controls | Checks | Frameworks |
| --- | --- | --- | --- |
| AWS | 31 | 57 | FedRAMP Moderate, PCI DSS 4.0.1, SOC 2 |
| Azure + Entra ID | 15 | 28 | FedRAMP Moderate, PCI DSS 4.0.1, SOC 2 |
| GitHub | 9 | 16 | FedRAMP Moderate, PCI DSS 4.0.1, SOC 2 |

The scanner uses read-only access and never modifies your environment.

## Troubleshooting

**"Cannot connect to AWS"** — Run `aws sts get-caller-identity` to verify credentials.

**"SubscriptionRequiredException" or "OptInRequired"** — AWS service not enabled. Reported as a finding, not an error.

**"Authorization_RequestDenied" for Azure** — Service principal needs `User.Read.All` and `Directory.Read.All` Application permissions with admin consent.

**Azure zero findings in Docker** — Check `.env` has correct credentials: `docker compose exec openframp env | grep AZURE`

**GitHub branch protection empty** — GitHub Rulesets (newer feature) are not yet supported by Steampipe. Classic branch protection rules are detected.

**Steampipe database conflict in Docker** — Don't run manual `steampipe query` inside a running container. Use the dashboard.

**Port 4000 in use** — Stop other services on 4000 or change the port in `docker-compose.yml`.

## Permissions

| Provider | Required Access |
| --- | --- |
| AWS | `SecurityAudit` managed policy. For Role: also `sts:AssumeRole` |
| Azure | `Reader` on subscription + `User.Read.All` + `Directory.Read.All` (Application, admin consented) |
| GitHub | Token with `repo`, `read:org`, `admin:repo_hook` |
