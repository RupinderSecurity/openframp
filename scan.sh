#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║           OpenFRAMP Compliance Scanner           ║${NC}"
echo -e "${CYAN}${BOLD}║     Open-Source FedRAMP Compliance Pipeline      ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Check dependencies
for cmd in steampipe opa python3; do
  if ! command -v $cmd &> /dev/null; then
    echo -e "${RED}ERROR: $cmd is not installed${NC}"
    exit 1
  fi
done

# Check AWS connectivity
echo -e "${CYAN}Verifying AWS connectivity...${NC}"
if ! steampipe query --output json "select account_id from aws_account" > /dev/null 2>&1; then
  echo -e "${RED}ERROR: Cannot connect to AWS. Check credentials.${NC}"
  exit 1
fi
echo -e "${GREEN}Connected.${NC}"
echo ""

# Run the pipeline
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

python3 oscal/scanner.py catalog/fedramp-moderate-aws.json

echo ""
echo -e "${CYAN}Output: oscal/assessment-results.json${NC}"
echo -e "${CYAN}View:   Load the JSON into the OSCAL Viewer${NC}"
echo ""