import json
import subprocess
import sys
from datetime import datetime
import uuid

# Step 1: Run Steampipe to get S3 bucket data
print("Running Steampipe scan...")
steampipe_result = subprocess.run(
    ["steampipe", "query", "--output", "json",
     "select name, block_public_acls, block_public_policy, restrict_public_buckets, ignore_public_acls from aws_s3_bucket"],
    capture_output=True, text=True
)
scan_data = json.loads(steampipe_result.stdout)

# Step 2: Run OPA against the scan data
print("Evaluating OPA policies...")
opa_result = subprocess.run(
    ["opa", "eval", "-i", "/dev/stdin", "-d", "checks/s3_public_access.rego",
     "data.openframp.s3"],
    input=steampipe_result.stdout,
    capture_output=True, text=True
)
opa_data = json.loads(opa_result.stdout)

# Pull out the pass/fail lists
findings = opa_data["result"][0]["expressions"][0]["value"]
denials = findings.get("deny", [])
passes = findings.get("pass", [])

print(f"Found {len(denials)} failures and {len(passes)} passes")

# Step 3: Build the OSCAL Assessment Results document
oscal_ar = {
    "assessment-results": {
        "uuid": str(uuid.uuid4()),
        "metadata": {
            "title": "OpenFRAMP Automated Assessment Results",
            "last-modified": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "version": "1.0.0",
            "oscal-version": "1.1.2"
        },
        "import-ap": {
            "href": "#placeholder-assessment-plan"
        },
        "results": [
            {
                "uuid": str(uuid.uuid4()),
                "title": "S3 Public Access Assessment",
                "description": "Automated scan of S3 bucket public access controls",
                "start": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "findings": [],
                "observations": []
            }
        ]
    }
}

result = oscal_ar["assessment-results"]["results"][0]

# Add each failure as a finding
for denial in denials:
    result["findings"].append({
        "uuid": str(uuid.uuid4()),
        "title": denial,
        "description": denial,
        "target": {
            "type": "objective-id",
            "target-id": "ac-3",
            "status": {"state": "not-satisfied"}
        }
    })

# Add each pass as a finding
for passed in passes:
    result["findings"].append({
        "uuid": str(uuid.uuid4()),
        "title": passed,
        "description": passed,
        "target": {
            "type": "objective-id",
            "target-id": "ac-3",
            "status": {"state": "satisfied"}
        }
    })

# Add raw scan data as an observation
result["observations"].append({
    "uuid": str(uuid.uuid4()),
    "description": "Raw Steampipe scan data for S3 buckets",
    "methods": ["TEST"],
    "collected": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "subjects": [
        {"subject-uuid": str(uuid.uuid4()), "type": "component",
         "title": row["name"],
         "props": [
             {"name": "block_public_acls", "value": str(row["block_public_acls"])},
             {"name": "block_public_policy", "value": str(row["block_public_policy"])},
             {"name": "restrict_public_buckets", "value": str(row["restrict_public_buckets"])}
         ]}
        for row in scan_data["rows"]
    ]
})

# Step 4: Write to file
output_path = "oscal/assessment-results.json"
with open(output_path, "w") as f:
    json.dump(oscal_ar, f, indent=2)

print(f"\nOSCAL Assessment Results written to {output_path}")
print(f"Total findings: {len(result['findings'])}")