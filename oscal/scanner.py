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
        stderr = result.stderr
        if "SubscriptionRequiredException" in stderr:
            return {"rows": [], "_not_enabled": True}, None
        if "does not exist" in stderr:
            return {"rows": [], "_not_found": True}, None
        return None, stderr
    return json.loads(result.stdout), None

def evaluate_check(check, query_result):
    findings = {"deny": [], "pass": []}
    severity = check.get("severity", "medium").upper()
    desc = check["description"]
    check_id = check["check_id"]
    
    if query_result is None:
        return findings
    
    if query_result.get("_not_enabled"):
        findings["deny"].append(f"{severity}: {desc} — service not enabled in this account")
        return findings
    
    if query_result.get("_not_found"):
        return findings
    
    rows = query_result.get("rows", [])
    
    if len(rows) == 0:
        zero_row_checks = ["au-2-cloudtrail-enabled", "au-6-guardduty-enabled",
                           "cm-6-config-enabled", "si-4-securityhub-enabled",
                           "ra-5-inspector-enabled"]
        if check_id in zero_row_checks:
            findings["deny"].append(f"{severity}: {desc} — none found")
        return findings
    
    for row in rows:
        name = (row.get("name") or row.get("instance_id") or row.get("volume_id") or
                row.get("db_instance_identifier") or row.get("group_id") or
                row.get("user_name") or row.get("vpc_id") or row.get("hub_arn") or
                row.get("detector_id") or "unknown")
        
        failed = False
        reason = ""
        
        if "mfa" in check_id:
            if row.get("mfa_enabled") == False:
                failed = True
                reason = "MFA not enabled"
            elif row.get("account_mfa_enabled") == 0:
                failed = True
                reason = "Root MFA not enabled"
        
        elif "encryption" in check_id or "encrypted" in check_id:
            enc = row.get("server_side_encryption_configuration") or row.get("encrypted") or row.get("storage_encrypted")
            if enc is None or enc == False:
                failed = True
                reason = "not encrypted"
        
        elif "public-access" in check_id:
            if row.get("block_public_acls") == False:
                failed = True
                reason = "public access allowed"
        
        elif "public-policy" in check_id:
            if row.get("bucket_policy_is_public") == True:
                failed = True
                reason = "public policy attached"
        
        elif "cloudtrail" in check_id and "encrypted" in check_id:
            if row.get("kms_key_id") is None:
                failed = True
                reason = "logs not encrypted with KMS"
        
        elif "cloudtrail" in check_id and "log-validation" in check_id:
            if row.get("log_file_validation_enabled") == False:
                failed = True
                reason = "log validation not enabled"
        
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
        
        elif "unrestricted" in check_id:
            if row.get("cidr_ipv4") == "0.0.0.0/0":
                ports = f"ports {row.get('from_port', '?')}-{row.get('to_port', '?')}"
                failed = True
                reason = f"open to internet on {ports}"
        
        elif "default-sg" in check_id:
            pass
        
        elif "flow" in check_id:
            if row.get("is_default") == True:
                failed = True
                reason = "VPC has no flow logs configured"
        
        elif "admin-access" in check_id:
            arns = str(row.get("attached_policy_arns", ""))
            if "AdministratorAccess" in arns:
                failed = True
                reason = "has AdministratorAccess"
        
        elif "inline-admin" in check_id:
            if row.get("inline_policies") not in [None, "null", "[]", ""]:
                failed = True
                reason = "has inline policies"
        
        elif "star" in check_id:
            policy = str(row.get("policy_std", ""))
            if '"Action":"*"' in policy and '"Resource":"*"' in policy:
                failed = True
                reason = "allows Action:* Resource:*"
        
        elif "password-length" in check_id:
            length = row.get("minimum_password_length", 0)
            if length < 14:
                failed = True
                reason = f"min length {length}, should be 14+"
        
        elif "password-lockout" in check_id:
            reuse = row.get("password_reuse_prevention", 0)
            if reuse == 0 or reuse is None:
                failed = True
                reason = "no password reuse prevention"
        
        elif "rotation" in check_id:
            if row.get("key_rotation_enabled") == False:
                failed = True
                reason = "key rotation not enabled"
        
        elif "access-key" in check_id or "rotated" in check_id:
            if row.get("status") == "Active":
                failed = True
                reason = f"active key created {row.get('create_date', 'unknown')}, verify rotation"
        
        elif "config" in check_id:
            if row.get("recording") in [False, None]:
                failed = True
                reason = "not recording"
        
        elif "guardduty" in check_id:
            if row.get("status") != "ENABLED":
                failed = True
                reason = "not enabled"
        
        elif "securityhub" in check_id:
            pass
        
        elif "versioning" in check_id:
            if row.get("versioning_enabled") == False:
                failed = True
                reason = "versioning not enabled"
        
        elif "tagged" in check_id:
            tags = row.get("tags")
            if tags is None or tags == {}:
                failed = True
                reason = "no tags"
        
        elif "fips" in check_id or "origin" in check_id:
            origin = row.get("origin", "")
            if origin not in ["AWS_KMS", "AWS_CLOUDHSM"]:
                failed = True
                reason = f"origin is {origin}, not FIPS-validated"
        
        elif "https" in check_id:
            protocol = row.get("protocol", "")
            if protocol not in ["HTTPS", "TLS"]:
                failed = True
                reason = f"protocol is {protocol}, not HTTPS/TLS"
        
        elif "ssm" in check_id:
            if row.get("ping_status") != "Online":
                failed = True
                reason = "not managed by SSM"
        
        elif "root-access-key" in check_id:
            if row.get("account_access_keys_present") == 1:
                failed = True
                reason = "root account has access keys"

        elif "backup" in check_id:
            retention = row.get("backup_retention_period", 0)
            if retention is None or retention == 0:
                failed = True
                reason = "automated backups not enabled"
        
        elif "multi-az" in check_id or "multi_az" in check_id:
            if row.get("multi_az") == False:
                failed = True
                reason = "not configured for Multi-AZ"
        
        elif "publicly-accessible" in check_id or "no-public" in check_id:
            if row.get("publicly_accessible") == True:
                failed = True
                reason = "publicly accessible"
        
        elif "nacl" in check_id:
            if row.get("cidr_block") == "0.0.0.0/0" and row.get("rule_action") == "allow":
                failed = True
                reason = "allows all traffic from 0.0.0.0/0"
        
        elif "lifecycle" in check_id:
            rules = row.get("lifecycle_rules")
            if rules is None or rules == "null" or rules == "[]":
                failed = True
                reason = "no lifecycle policy configured"
        
        elif "logging" in check_id and "s3" in check_id:
            logging = row.get("logging")
            if logging is None or logging == {} or logging == "null":
                failed = True
                reason = "access logging not enabled"
        
        elif "imdsv2" in check_id:
            opts = str(row.get("metadata_options", ""))
            if "HttpTokens" not in opts or '"HttpTokens":"required"' not in opts.replace(" ", ""):
                failed = True
                reason = "IMDSv2 not enforced"
        
        elif "outbound" in check_id or "egress" in check_id:
            if row.get("cidr_ipv4") == "0.0.0.0/0":
                failed = True
                reason = "unrestricted outbound to 0.0.0.0/0"
        
        elif "password-reuse" in check_id:
            reuse = row.get("password_reuse_prevention")
            if reuse is None or reuse < 24:
                failed = True
                reason = f"password reuse prevention is {reuse}, should be 24"
        
        elif "password-max-age" in check_id:
            age = row.get("max_password_age")
            if age is None or age == 0 or age > 90:
                failed = True
                reason = f"max password age is {age}, should be 90 or less"
        
        elif "cloudfront" in check_id:
            policy = row.get("viewer_protocol_policy", "")
            if policy != "https-only" and policy != "redirect-to-https":
                failed = True
                reason = f"viewer protocol is {policy}, should be https-only"
        
        elif "scan-on-push" in check_id:
            config = str(row.get("image_scanning_configuration", ""))
            if "true" not in config.lower():
                failed = True
                reason = "scan on push not enabled"
        
        elif "sns-topic" in check_id or "alarm" in check_id:
            pass  # existence is the check — if rows exist, it passes
        
        elif "point-in-time" in check_id or "dynamodb-backup" in check_id:
            pitr = str(row.get("point_in_time_recovery_description", ""))
            if "ENABLED" not in pitr.upper():
                failed = True
                reason = "point-in-time recovery not enabled"
        
        if failed:
            findings["deny"].append(f"{severity}: {name} — {reason} ({desc})")
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
        control_denies = []
        control_passes = []
        
        print(f"  [{control['control_id']}] {control['title']}")
        
        for check in control["checks"]:
            total_checks += 1
            query_result, error = run_query(check["query"])
            
            if error:
                print(f"    ⚠ {check['check_id']}: query error")
                total_errors += 1
                continue
            
            findings = evaluate_check(check, query_result)
            
            denials = findings.get("deny", [])
            passes = findings.get("pass", [])
            
            control_denies.extend(denials)
            control_passes.extend(passes)
            
            if len(denials) > 0:
                print(f"    ✗ {check['check_id']}: {len(denials)} failed")
            elif len(passes) > 0:
                print(f"    ✓ {check['check_id']}: {len(passes)} passed")
        
        total_pass += len(control_passes)
        total_fail += len(control_denies)
        
        all_results.append({
            "control_id": control["control_id"],
            "title": control["title"],
            "deny": control_denies,
            "pass": control_passes
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