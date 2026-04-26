#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║           OpenFRAMP Compliance Scanner           ║${NC}"
echo -e "${CYAN}${BOLD}║     Open-Source Multi-Framework Pipeline         ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

for cmd in steampipe opa python3; do
  if ! command -v $cmd &> /dev/null; then
    echo -e "${RED}ERROR: $cmd is not installed${NC}"
    exit 1
  fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CATALOG="${1:-all}"

if [ "$CATALOG" = "all" ]; then
  for catalog_file in catalog/*.json; do
    echo -e "${CYAN}Running: $catalog_file${NC}"
    echo ""
    python3 oscal/scanner.py "$catalog_file"
    echo ""
  done
elif [ -f "$CATALOG" ]; then
  python3 oscal/scanner.py "$CATALOG"
else
  echo -e "${RED}ERROR: Catalog not found: $CATALOG${NC}"
  echo "Usage: ./scan.sh [catalog-file|all]"
  echo "Available catalogs:"
  ls catalog/*.json
  exit 1
fi

echo -e "${CYAN}View: Load oscal/assessment-results.json into the OSCAL Viewer${NC}"
echo ""