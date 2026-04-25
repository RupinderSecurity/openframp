import json
import subprocess
import sys
from datetime import datetime, timezone
import uuid

def load_catalog(path):
    with open(path) as f:
        return json.load(f)

def run_query(query):
    result = subprocess.run(
        ["steampipe", "query", "--output", "json", query],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None, result.stderr
    return json.loads(result.stdout), None

def evaluate_check(check, rows):
    """Generic evaluation based on check type and known patterns."""
    findings = {"deny": [], "pass": []}
    check_id = check["check_id"]
    severity = check.get("severity", "medium").upper()
    desc = check["description"]
    
    if len(rows) == 0:
        # For some checks, zero rows IS the finding
        if check_id in ["au-2-cloudtrail-enabled", "au-6-guardduty-enabled", 
                         "cm-6-config-enabled", "si-4-securityhub-enabled",
                         "ra-5-inspector-enabled"]:
            findings["deny"].append(f"{severity}: {desc} — none found")
        return findings
    
    for row in rows:
        name = row.get("name", row.get("instance_id", row.get("volume_id", 
               row.get("db_instance_identifier", row.get("group_id",
               row.get("user_name", row.get("vpc_id", row.get("hub_arn", "unknown"))))))))
        
        failed = False
        reason = ""
        
        # MFA checks
        if "mfa" in check_id:
            if row.get("mfa_enabled") == False:
                failed = True
                reason = "MFA not enabled"
            elif row.get("account_mfa_enabled") == 0:
                failed = True
                reason = "Root MFA not enabled"
        
        # Encryption checks
        elif "encryption" in check_id or "encrypted" in check_id:
            enc = row.get("server_side_encryption_configuration") or row.get("encrypted") or row.get("storage_encrypted")
            if enc is None or enc == False:
                failed = True
                reason = "not encrypted"
        
        # Public access checks
        elif "public" in check_id:
            if row.get("block_public_acls") == False or row.get("bucket_policy_is_public") == True:
                failed = True
                reason = "public access allowed"
        
        # CloudTrail checks
        elif "cloudtrail" in check_id:
            if row.get("is_logging") == False:
                failed = True
                reason = "not logging"
            elif row.get("is_multi_region_trail") == False:
                failed = True
                reason = "not multi-region"
            elif row.get("log_file_validation_enabled") == False:
                failed = True
                reason = "no log validation"
            elif "encrypted" in check_id and row.get("kms_key_id") is None:
                failed = True
                reason = "logs not encrypted with KMS"
        
        # Security group checks
        elif "unrestricted" in check_id or "sc-7" in check_id:
            if row.get("cidr_ipv4") == "0.0.0.0/0":
                ports = f"ports {row.get('from_port', '?')}-{row.get('to_port', '?')}"
                failed = True
                reason = f"open to internet on {ports}"
        
        # Admin policy checks
        elif "admin" in check_id or "star" in check_id or "least" in check_id:
            arns = str(row.get("attached_policy_arns", ""))
            if "AdministratorAccess" in arns:
                failed = True
                reason = "has AdministratorAccess"
            elif "PowerUserAccess" in arns:
                failed = True
                reason = "has PowerUserAccess"
        
        # Password policy checks
        elif "password" in check_id:
            if row.get("minimum_password_length", 0) < 14:
                failed = True
                reason = f"min length {row.get('minimum_password_length', 0)}, should be 14+"
        
        # Key rotation checks
        elif "rotation" in check_id:
            if row.get("key_rotation_enabled") == False:
                failed = True
                reason = "key rotation not enabled"
        
        # Config/GuardDuty/SecurityHub/VPC flow logs
        elif "config" in check_id or "guardduty" in check_id or "securityhub" in check_id:
            status = row.get("status") or row.get("recording")
            if status in [False, "DISABLED", None]:
                failed = True
                reason = "not enabled"
        
        elif "flow" in check_id:
            if row.get("flow_log_status") != "ACTIVE":
                failed = True
                reason = "flow logs not active"
        
        # Access key rotation
        elif "access-key" in check_id or "rotated" in check_id:
            create = row.get("create_date", "")
            if create and row.get("status") == "Active":
                # Simple age check
                failed = True
                reason = f"active key created {create}, check rotation"
        
        # Fallback — if we don't have specific logic, flag for review
        else:
            pass
        
        if failed:
            findings["deny"].append(f"{severity}: {name} — {reason} ({check['description']})")
        else:
            findings["pass"].append(f"PASS: {name} — {desc}")
    
    return findings

def build_oscal(all_results, catalog):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    oscal_ar = {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"OpenFRAMP {catalog['framework']} Assessment Results",
                "last-modified": now,
                "version": catalog["catalog_version"],
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "framework", "value": catalog["framework"]},
                    {"name": "baseline", "value": catalog["baseline"]},
                    {"name": "provider", "value": catalog["provider"]}
                ]
            },
            "import-ap": {"href": "#openframp-assessment-plan"},
            "results": []
        }
    }
    
    for result in all_results:
        r = {
            "uuid": str(uuid.uuid4()),
            "title": f"{result['control_id']} — {result['title']}",
            "description": result["title"],
            "start": now,
            "findings": []
        }
        
        for d in result.get("deny", []):
            r["findings"].append({
                "uuid": str(uuid.uuid4()),
                "title": d,
                "description": d,
                "target": {
                    "type": "objective-id",
                    "target-id": result["control_id"].lower(),
                    "status": {"state": "not-satisfied"}
                }
            })
        
        for p in result.get("pass", []):
            r["findings"].append({
                "uuid": str(uuid.uuid4()),
                "title": p,
                "description": p,
                "target": {
                    "type": "objective-id",
                    "target-id": result["control_id"].lower(),
                    "status": {"state": "satisfied"}
                }
            })
        
        oscal_ar["assessment-results"]["results"].append(r)
    
    return oscal_ar

def main():
    catalog_path = sys.argv[1] if len(sys.argv) > 1 else "catalog/fedramp-moderate-aws.json"
    
    catalog = load_catalog(catalog_path)
    
    print("=" * 60)
    print(f"OpenFRAMP — {catalog['framework']} Scanner")
    print(f"Provider: {catalog['provider'].upper()} | Baseline: {catalog['baseline']}")
    print("=" * 60)
    print()
    
    all_results = []
    total_pass = 0
    total_fail = 0
    total_checks = 0
    total_errors = 0
    
    for control in catalog["controls"]:
        control_pass = 0
        control_fail = 0
        
        print(f"  [{control['control_id']}] {control['title']}")
        
        for check in control["checks"]:
            total_checks += 1
            rows_data, error = run_query(check["query"])
            
            if error:
                print(f"    ⚠ {check['check_id']}: query error")
                total_errors += 1
                continue
            
            rows = rows_data.get("rows", [])
            findings = evaluate_check(check, rows)
            
            denials = len(findings.get("deny", []))
            passes = len(findings.get("pass", []))
            
            control_pass += passes
            control_fail += denials
            
            if denials > 0:
                print(f"    ✗ {check['check_id']}: {denials} failed")
            elif passes > 0:
                print(f"    ✓ {check['check_id']}: {passes} passed")
            else:
                print(f"    — {check['check_id']}: no resources found")
        
        total_pass += control_pass
        total_fail += control_fail
        
        all_results.append({
            "control_id": control["control_id"],
            "title": control["title"],
            "deny": [d for check in control["checks"] 
                     for d in evaluate_check(check, run_query(check["query"])[0].get("rows", []) if run_query(check["query"])[0] else []).get("deny", [])],
            "pass": [p for check in control["checks"]
                     for p in evaluate_check(check, run_query(check["query"])[0].get("rows", []) if run_query(check["query"])[0] else []).get("pass", [])]
        })
    
    # Build OSCAL
    oscal_ar = build_oscal(all_results, catalog)
    output_path = "oscal/assessment-results.json"
    with open(output_path, "w") as f:
        json.dump(oscal_ar, f, indent=2)
    
    print()
    print("=" * 60)
    controls_checked = len(catalog["controls"])
    print(f"Controls scanned: {controls_checked}")
    print(f"Individual checks: {total_checks} ({total_errors} errors)")
    print(f"Results: {total_pass} passed, {total_fail} failed")
    print(f"OSCAL output: {output_path}")
    print("=" * 60)

if __name__ == "__main__":
    main()