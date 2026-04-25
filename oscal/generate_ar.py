import json
import subprocess
import sys
from datetime import datetime, timezone
import uuid

def run_check(name, query, rego_file, rego_path):
    print(f"  Scanning: {name}...")
    
    steampipe = subprocess.run(
        ["steampipe", "query", "--output", "json", query],
        capture_output=True, text=True
    )
    
    if steampipe.returncode != 0:
        print(f"  WARNING: Steampipe failed for {name}: {steampipe.stderr}")
        return {"deny": [], "pass": []}, {"rows": []}
    
    scan_data = json.loads(steampipe.stdout)
    
    opa = subprocess.run(
        ["opa", "eval", "-i", "/dev/stdin", "-d", rego_file, rego_path],
        input=steampipe.stdout,
        capture_output=True, text=True
    )
    
    if opa.returncode != 0:
        print(f"  WARNING: OPA failed for {name}: {opa.stderr}")
        return {"deny": [], "pass": []}, scan_data
    
    opa_data = json.loads(opa.stdout)
    findings = opa_data["result"][0]["expressions"][0]["value"]
    
    denials = findings.get("deny", [])
    passes = findings.get("pass", [])
    print(f"  Results: {len(denials)} failures, {len(passes)} passes")
    
    return findings, scan_data

def build_oscal(all_results):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    oscal_ar = {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "OpenFRAMP Automated Assessment Results",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": "1.1.2"
            },
            "import-ap": {
                "href": "#placeholder-assessment-plan"
            },
            "results": []
        }
    }
    
    for check in all_results:
        result = {
            "uuid": str(uuid.uuid4()),
            "title": check["title"],
            "description": check["description"],
            "start": now,
            "findings": [],
            "observations": []
        }
        
        for denial in check["findings"].get("deny", []):
            result["findings"].append({
                "uuid": str(uuid.uuid4()),
                "title": denial,
                "description": denial,
                "target": {
                    "type": "objective-id",
                    "target-id": check["control_id"],
                    "status": {"state": "not-satisfied"}
                }
            })
        
        for passed in check["findings"].get("pass", []):
            result["findings"].append({
                "uuid": str(uuid.uuid4()),
                "title": passed,
                "description": passed,
                "target": {
                    "type": "objective-id",
                    "target-id": check["control_id"],
                    "status": {"state": "satisfied"}
                }
            })
        
        if check["scan_data"].get("rows"):
            subjects = []
            for row in check["scan_data"]["rows"]:
                name_field = row.get("name", row.get("group_id", row.get("id", "unknown")))
                props = [
                    {"name": k, "value": str(v)}
                    for k, v in row.items()
                    if k not in ("name", "group_id", "id")
                ]
                subjects.append({
                    "subject-uuid": str(uuid.uuid4()),
                    "type": "component",
                    "title": str(name_field),
                    "props": props
                })
            
            result["observations"].append({
                "uuid": str(uuid.uuid4()),
                "description": f"Raw scan data for {check['title']}",
                "methods": ["TEST"],
                "collected": now,
                "subjects": subjects
            })
        
        oscal_ar["assessment-results"]["results"].append(result)
    
    return oscal_ar

def main():
    print("=" * 60)
    print("OpenFRAMP — Automated Compliance Scanner")
    print("=" * 60)
    print()
    
    checks = [
        {
            "title": "S3 Public Access Assessment",
            "description": "Check S3 buckets for public access controls",
            "control_id": "ac-3",
            "query": "select name, block_public_acls, block_public_policy, restrict_public_buckets, ignore_public_acls from aws_s3_bucket",
            "rego_file": "checks/s3_public_access.rego",
            "rego_path": "data.openframp.s3"
        },
        {
            "title": "IAM MFA Assessment",
            "description": "Check IAM users for MFA enforcement",
            "control_id": "ia-2",
            "query": "select name, mfa_enabled, password_last_used, create_date from aws_iam_user",
            "rego_file": "checks/iam_mfa.rego",
            "rego_path": "data.openframp.iam"
        },
        {
            "title": "S3 Encryption Assessment",
            "description": "Check S3 buckets for encryption at rest",
            "control_id": "sc-28",
            "query": "select name, server_side_encryption_configuration from aws_s3_bucket",
            "rego_file": "checks/encryption.rego",
            "rego_path": "data.openframp.encryption"
        },
        {
            "title": "CloudTrail Logging Assessment",
            "description": "Check for active CloudTrail with multi-region and log validation",
            "control_id": "au-2",
            "query": "select name, is_logging, is_multi_region_trail, log_file_validation_enabled from aws_cloudtrail_trail",
            "rego_file": "checks/cloudtrail.rego",
            "rego_path": "data.openframp.cloudtrail"
        },
        {
            "title": "Security Group Assessment",
            "description": "Check for security groups open to the internet",
            "control_id": "sc-7",
            "query": "select group_id, from_port, to_port, cidr_ipv4, ip_protocol, type from aws_vpc_security_group_rule where type = 'ingress'",
            "rego_file": "checks/security_groups.rego",
            "rego_path": "data.openframp.securitygroups"
        },
        {
            "title": "Least Privilege Assessment",
            "description": "Check IAM users for overly broad policies",
            "control_id": "ac-6",
            "query": "select name, attached_policy_arns from aws_iam_user",
            "rego_file": "checks/least_privilege.rego",
            "rego_path": "data.openframp.leastprivilege"
        }
    ]
    
    all_results = []
    total_pass = 0
    total_fail = 0
    
    for check in checks:
        findings, scan_data = run_check(
            check["title"],
            check["query"],
            check["rego_file"],
            check["rego_path"]
        )
        
        denials = len(findings.get("deny", []))
        passes = len(findings.get("pass", []))
        total_pass += passes
        total_fail += denials
        
        all_results.append({
            "title": check["title"],
            "description": check["description"],
            "control_id": check["control_id"],
            "findings": findings,
            "scan_data": scan_data
        })
    
    oscal_ar = build_oscal(all_results)
    
    output_path = "oscal/assessment-results.json"
    with open(output_path, "w") as f:
        json.dump(oscal_ar, f, indent=2)
    
    print()
    print("=" * 60)
    print(f"TOTAL: {total_pass} passed, {total_fail} failed")
    print(f"Controls covered: AC-3, IA-2, SC-28, AU-2, SC-7, AC-6")
    print(f"OSCAL Assessment Results written to {output_path}")
    print("=" * 60)

if __name__ == "__main__":
    main()