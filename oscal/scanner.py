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
        if any(e in stderr for e in ["SubscriptionRequiredException", "OptInRequired", "AccessDeniedException", "UnauthorizedOperation", "AccessDenied", "required scopes", "PremiumTenantOrB2CTenant", "premium license", "required permissions", "Forbidden", "does not exist", "unauthorized operation"]):
            return {"rows": [], "_not_enabled": True}, None
        if "Dependabot alerts are disabled" in stderr:
            return {"rows": [], "_not_enabled": True}, None
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
                           "ra-5-inspector-enabled",
                           "ac-6-branch-protection-enabled", "ac-6-branch-no-force-push",
                           "ac-6-branch-no-deletions", "cm-3-branch-requires-pr",
                           "cm-3-branch-requires-status-checks",
                           "cm-3-branch-requires-conversation-resolution",
                           "cm-3-branch-dismisses-stale-reviews",
                           "sa-11-branch-requires-code-owner-review",
                           "si-7-commit-signatures-required", "si-7-branch-linear-history", 
                           "au-12-cloudwatch-log-groups", "au-2-entra-audit-logs", 
                           "au-2-entra-sign-in-logs", "cp-9-backup-plan-exists",
                           "ia-2-conditional-access-policies",
                           "sa-11-codeowners-exists",
                           "cm-2-community-profile-readme",
                           "cm-2-community-profile-contributing",
                           "cm-2-community-profile-code-of-conduct", "sc-7-waf-web-acl-exists",
                           "ac-2-root-account-usage-alarm", "ac-3-branch-restricts-pushes"]
        if check_id in zero_row_checks:
            findings["deny"].append(f"{severity}: {desc} — none found")
        return findings
    
    for row in rows:
        name = (row.get("name") or row.get("name_with_owner") or row.get("repository_full_name") or
                row.get("instance_id") or row.get("volume_id") or
                row.get("db_instance_identifier") or row.get("group_id") or
                row.get("user_name") or row.get("vpc_id") or row.get("hub_arn") or
                row.get("detector_id") or row.get("topic_arn") or row.get("display_name") or
                row.get("user_principal_name") or "unknown")
        
        failed = False
        reason = ""
        
        if "mfa" in check_id:
            if row.get("mfa_enabled") == False:
                failed = True
                reason = "MFA not enabled"
            elif row.get("account_mfa_enabled") == 0:
                failed = True
                reason = "Root MFA not enabled"
        
        elif "storage" in check_id and "encryption" in check_id and "sc-28" in check_id:
            key_source = row.get("encryption_key_source", "")
            if not key_source:
                failed = True
                reason = "encryption not configured"
        
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

        elif "config-enabled" in check_id:
            if row.get("status_recording") != True:
                failed = True
                reason = "AWS Config recorder not actively recording"
        
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
        
        elif "https" in check_id and "storage" not in check_id and "app-service" not in check_id:
            protocol = row.get("protocol", "")
            if protocol not in ["HTTPS", "TLS"]:
                failed = True
                reason = f"protocol is {protocol}, not HTTPS/TLS"
        
        elif "ssm" in check_id:
            if row.get("ping_status") != "Online":
                failed = True
                reason = "not managed by SSM"

        elif "storage" in check_id and "public-access" in check_id:
            if row.get("allow_blob_public_access") == True:
                failed = True
                reason = "public blob access allowed"
        
        elif "storage" in check_id and "public-network" in check_id:
            action = row.get("network_rule_default_action", "")
            if action != "Deny":
                failed = True
                reason = f"default network action is {action}, should be Deny"
        
        elif "app-service" in check_id and "https" in check_id:
            if row.get("https_only") != True:
                failed = True
                reason = "HTTPS not enforced"
        
        elif "storage" in check_id and "https" in check_id:
            if row.get("enable_https_traffic_only") == False:
                failed = True
                reason = "HTTPS not required"
        
        elif "min-tls" in check_id or "tls" in check_id:
            tls = row.get("minimum_tls_version") or row.get("minimal_tls_version") or ""
            if tls not in ["TLS1_2", "1.2"]:
                failed = True
                reason = f"TLS version is {tls}, should be 1.2"
        
        elif "nsg" in check_id and ("ssh" in check_id or "rdp" in check_id or "unrestricted" in check_id):
            rules = row.get("security_rules", "[]")
            if isinstance(rules, str):
                import json as json_mod
                try:
                    rules = json_mod.loads(rules)
                except:
                    rules = []
            target_port = "22" if "ssh" in check_id else "3389" if "rdp" in check_id else "*"
            for rule in rules:
                props = rule.get("properties", rule)
                if (props.get("access") == "Allow" and
                    props.get("direction") == "Inbound" and
                    props.get("sourceAddressPrefix") == "*" and
                    (props.get("destinationPortRange") == target_port or props.get("destinationPortRange") == "*")):
                    failed = True
                    reason = f"allows {target_port} inbound from * ({props.get('name', rule.get('name', 'unnamed'))})"
                    break
        
        elif "keyvault" in check_id and "soft-delete" in check_id:
            if row.get("soft_delete_enabled") != True:
                failed = True
                reason = "soft delete not enabled"
        
        elif "keyvault" in check_id and "purge" in check_id:
            if row.get("purge_protection_enabled") != True:
                failed = True
                reason = "purge protection not enabled"
        
        elif "keyvault" in check_id and "expiry" in check_id:
            if row.get("expires_at") is None:
                failed = True
                reason = "no expiration date set"
        
        elif "defender" in check_id or "pricing" in check_id:
            tier = row.get("pricing_tier", "")
            if tier == "Free":
                failed = True
                reason = f"Defender pricing tier is Free, should be Standard"
        
        elif "conditional-access" in check_id:
            state = row.get("state", "")
            if state != "enabled":
                failed = True
                reason = f"policy state is {state}"
        
        elif "guest" in check_id:
            failed = True
            reason = f"guest user found: {row.get('user_principal_name', 'unknown')}"
        
        elif "global-admin" in check_id:
            pass  # existence noted, not auto-failed — but count matters
        
        elif "sql" in check_id and "encryption" in check_id:
            tde = str(row.get("transparent_data_encryption", ""))
            if "Enabled" not in tde:
                failed = True
                reason = "transparent data encryption not enabled"
        
        elif "disk-encryption" in check_id:
            enc_type = row.get("encryption_type", "")
            if not enc_type or enc_type == "None":
                failed = True
                reason = "disk not encrypted"
        
        elif "flow-log" in check_id or "flow_log" in check_id:
            if row.get("network_watcher_flow_analytics_enabled") != True:
                failed = True
                reason = "flow logs not enabled"
        
        elif "security-contact" in check_id:
            email = row.get("email", "")
            if not email:
                failed = True
                reason = "no security contact email configured"
        
        elif "alert" in check_id and "log" in check_id:
            if row.get("enabled") != True:
                failed = True
                reason = "alert not enabled"
        
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
        
        elif "branch-protection" in check_id and "enabled" in check_id:
            pass  # if rows exist, protection is enabled — that's a pass
        
        elif "force-push" in check_id:
            if row.get("allows_force_pushes") == True:
                failed = True
                reason = "force pushes allowed"
        
        elif "no-deletions" in check_id or "branch" in check_id and "deletion" in check_id:
            if row.get("allows_deletions") == True:
                failed = True
                reason = "branch deletions allowed"
        
        elif "requires-pr" in check_id:
            if row.get("requires_approving_reviews") != True:
                failed = True
                reason = "pull request reviews not required"
        
        elif "status-checks" in check_id:
            if row.get("requires_status_checks") != True:
                failed = True
                reason = "status checks not required"
        
        elif "conversation-resolution" in check_id:
            if row.get("requires_conversation_resolution") != True:
                failed = True
                reason = "conversation resolution not required"
        
        elif "stale-reviews" in check_id:
            if row.get("dismisses_stale_reviews") != True:
                failed = True
                reason = "stale reviews not dismissed"
        
        elif "code-owner" in check_id:
            if row.get("requires_code_owner_reviews") != True:
                failed = True
                reason = "code owner reviews not required"
        
        elif "commit-signature" in check_id:
            if row.get("requires_commit_signatures") != True:
                failed = True
                reason = "signed commits not required"
        
        elif "linear-history" in check_id:
            if row.get("requires_linear_history") != True:
                failed = True
                reason = "linear history not required"
        
        elif "vulnerability-alerts" in check_id:
            if row.get("has_vulnerability_alerts_enabled") != True:
                failed = True
                reason = "Dependabot vulnerability alerts not enabled"
        
        elif "dependabot" in check_id and "open" in check_id:
            if row.get("state") == "open":
                failed = True
                reason = f"open Dependabot alert #{row.get('alert_number', '?')}"
        
        elif "security-policy" in check_id:
            if row.get("is_security_policy_enabled") != True:
                failed = True
                reason = "no SECURITY.md file"
        
        elif "license" in check_id:
            if row.get("license_info") is None:
                failed = True
                reason = "no license defined"
        
        elif "wiki-disabled" in check_id:
            if row.get("has_wiki_enabled") == True:
                failed = True
                reason = "wiki enabled (disable unless actively used)"
        
        elif "signoff" in check_id:
            if row.get("web_commit_signoff_required") != True:
                failed = True
                reason = "web commit sign-off not required"
        
        elif "exposed-secrets" in check_id:
            pass  # secrets existing in Actions is normal — this is informational
        
        elif "repo-not-public" in check_id:
            pass  # public repos are fine for open source — informational only

        elif "ebs-snapshot" in check_id and "encryption" in check_id:
            if row.get("encrypted") == False:
                failed = True
                reason = "snapshot not encrypted"
        
        elif "rds-snapshot" in check_id and "encryption" in check_id:
            if row.get("encrypted") == False:
                failed = True
                reason = "snapshot not encrypted"
        
        elif "rds-snapshot" in check_id and "public" in check_id:
            failed = True
            reason = "public RDS snapshot found"
        
        elif "ebs-snapshot" in check_id and "public" in check_id:
            perms = str(row.get("create_volume_permissions", ""))
            if "all" in perms.lower():
                failed = True
                reason = "snapshot is publicly shared"
        
        elif "secrets" in check_id and "rotation" in check_id:
            if row.get("rotation_enabled") != True:
                failed = True
                reason = "automatic rotation not enabled"
        
        elif "secrets" in check_id and "encrypted" in check_id:
            if row.get("kms_key_id") is None:
                failed = True
                reason = "using default encryption, not customer KMS"
        
        elif "cloudwatch" in check_id and "retention" in check_id:
            retention = row.get("retention_in_days")
            if retention is None or retention == 0:
                failed = True
                reason = "retention set to indefinite (should have explicit period)"
        
        elif "cloudwatch" in check_id and "encrypted" in check_id:
            if row.get("kms_key_id") is None:
                failed = True
                reason = "log group not encrypted with KMS"
        
        elif "lambda" in check_id and "runtime" in check_id:
            runtime = row.get("runtime", "")
            deprecated = ["python2.7", "python3.6", "python3.7", "nodejs10.x", "nodejs12.x", "dotnetcore2.1", "ruby2.5"]
            if runtime in deprecated:
                failed = True
                reason = f"deprecated runtime: {runtime}"
        
        elif "lambda" in check_id and "public" in check_id:
            policy = str(row.get("policy_std", ""))
            if '"Principal":"*"' in policy.replace(" ", ""):
                failed = True
                reason = "Lambda has public access policy"
        
        elif "lambda" in check_id and "url" in check_id:
            url_config = str(row.get("url_config", ""))
            if "NONE" in url_config:
                failed = True
                reason = "function URL allows unauthenticated access"
        
        elif "ebs-default-encryption" in check_id:
            if row.get("default_ebs_encryption_enabled") != True:
                failed = True
                reason = "EBS default encryption not enabled in this region"
        
        elif "ecr" in check_id and "immutability" in check_id:
            if row.get("image_tag_mutability") != "IMMUTABLE":
                failed = True
                reason = "image tags are mutable"
        
        elif "s3-data-events" in check_id:
            selectors = str(row.get("event_selectors", ""))
            if "S3" not in selectors:
                failed = True
                reason = "S3 data events not configured"
        
        elif "account-public-access-block" in check_id:
            if (row.get("block_public_acls") != True or 
                row.get("block_public_policy") != True or
                row.get("restrict_public_buckets") != True or
                row.get("ignore_public_acls") != True):
                failed = True
                reason = "account-level S3 public access block not fully enabled"
        
        elif "s3-versioning" in check_id or "cp-9" in check_id and "versioning" in check_id:
            if row.get("versioning_enabled") != True:
                failed = True
                reason = "versioning not enabled"
        
        elif "iam-group" in check_id:
            pass  # groups existing is informational
        
        elif "kms" in check_id and "pending-deletion" in check_id:
            failed = True
            reason = f"KMS key scheduled for deletion: {row.get('key_state', '')}"

        elif "security-defaults" in check_id:
            if row.get("is_enabled") != True:
                failed = True
                reason = "security defaults not enabled"
        
        elif "guest-invite" in check_id or "authorization-policy" in check_id:
            invite = row.get("allow_invites_from", "")
            if invite in ["everyone", "adminsAndGuestInviters"]:
                failed = True
                reason = f"guest invite policy is {invite}, should be restricted"
        
        
        elif "auto-provisioning" in check_id:
            props = str(row.get("properties", ""))
            if "On" not in props:
                failed = True
                reason = "auto-provisioning not enabled"
        
        elif "external-identity" in check_id:
            pass  # informational — existence check
        
        elif "device-registration" in check_id:
            pass  # informational — existence check
        
        elif "sign-in-log" in check_id or "audit-log" in check_id:
            pass  # if rows exist, logs are available — pass
        
        elif "entra-group" in check_id:
            pass  # groups existing is informational
        
        elif "privileged-role" in check_id:
            pass  # informational — count matters but not auto-fail
        
        elif "delete-branch-on-merge" in check_id:
            if row.get("delete_branch_on_merge") != True:
                failed = True
                reason = "branches not deleted after merge"
        
        elif "last-push-approval" in check_id:
            if row.get("require_last_push_approval") != True:
                failed = True
                reason = "last push approval not required"
        
        elif "forking-restricted" in check_id:
            failed = True
            reason = "private repo allows forking"
        
        elif "dependabot" in check_id and "critical" in check_id:
            if row.get("state") == "open":
                failed = True
                reason = f"open critical alert #{row.get('alert_number', '?')}"

        elif "config-enabled" in check_id:
            if row.get("status_recording") != True:
                failed = True
                reason = "AWS Config recorder not actively recording"

        elif "rds" in check_id and "encryption" in check_id:
            if row.get("storage_encrypted") != True:
                failed = True
                reason = "RDS instance not encrypted at rest"
        
        elif "rds" in check_id and "ssl" in check_id:
            cert = row.get("ca_cert_identifier", "")
            if not cert:
                failed = True
                reason = "no CA certificate configured for SSL"
        
        elif "rds" in check_id and "backup" in check_id:
            retention = row.get("backup_retention_period", 0)
            if retention is None or retention < 7:
                failed = True
                reason = f"backup retention is {retention} days (should be >= 7)"
        
        elif "rds" in check_id and "multi-az" in check_id:
            if row.get("multi_az") != True:
                failed = True
                reason = "not configured for Multi-AZ"
        
        elif "rds" in check_id and "public" in check_id:
            if row.get("publicly_accessible") == True:
                failed = True
                reason = "RDS instance is publicly accessible"
        
        elif "rds" in check_id and "logging" in check_id:
            logs = row.get("enabled_cloudwatch_logs_exports", [])
            if not logs:
                failed = True
                reason = "no CloudWatch log exports enabled"
        
        elif "dynamodb" in check_id and "encryption" in check_id:
            sse = str(row.get("sse_description", ""))
            if "KMS" not in sse and "ENABLED" not in sse.upper():
                failed = True
                reason = "using default AWS-owned key, not customer KMS"
        
        elif "dynamodb" in check_id and "pitr" in check_id:
            pitr = str(row.get("point_in_time_recovery_description", ""))
            if "ENABLED" not in pitr.upper():
                failed = True
                reason = "point-in-time recovery not enabled"
        
        elif "dynamodb" in check_id and "tagged" in check_id:
            tags = row.get("tags")
            if not tags:
                failed = True
                reason = "no tags"
        
        elif "ecs" in check_id and "container-insights" in check_id:
            settings = str(row.get("settings", ""))
            if "containerInsights" not in settings or "enabled" not in settings:
                failed = True
                reason = "Container Insights not enabled"
        
        elif "acm" in check_id and "expiry" in check_id:
            from datetime import datetime, timezone
            not_after = row.get("not_after", "")
            if not_after:
                try:
                    exp = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                    days_left = (exp - datetime.now(timezone.utc)).days
                    if days_left < 30:
                        failed = True
                        reason = f"certificate expires in {days_left} days"
                except:
                    pass
        
        elif "acm" in check_id and "renewal" in check_id:
            eligibility = row.get("renewal_eligibility", "")
            if eligibility == "INELIGIBLE":
                failed = True
                reason = "certificate not eligible for auto-renewal"
        
        elif "backup-vault" in check_id and "encrypted" in check_id:
            key = row.get("encryption_key_arn", "")
            if not key:
                failed = True
                reason = "backup vault not encrypted with KMS"
        
        elif "sns" in check_id and "encryption" in check_id:
            key = row.get("kms_master_key_id", "")
            if not key:
                failed = True
                reason = "SNS topic not encrypted with KMS"
        
        elif "sqs" in check_id and "encryption" in check_id:
            kms = row.get("kms_master_key_id", "")
            sse = row.get("sqs_managed_sse_enabled", False)
            if not kms and sse != True:
                failed = True
                reason = "SQS queue not encrypted"
        
        elif "ssm" in check_id and "managed" in check_id:
            status = row.get("ping_status", "")
            if status != "Online":
                failed = True
                reason = f"SSM agent status: {status} (should be Online)"
        
        elif "managed-disk" in check_id and "encryption" in check_id:
            enc_type = row.get("encryption_type", "")
            if not enc_type:
                failed = True
                reason = "managed disk not encrypted"
        
        elif "vm-disk-encryption" in check_id:
            enc = str(row.get("os_disk_encryption_settings", ""))
            if not enc or enc == "None":
                pass  # Azure encrypts by default, don't false positive
        
        elif "vm-extensions" in check_id:
            pass  # informational
        
        elif "vm" in check_id and "tagged" in check_id:
            tags = row.get("tags")
            if not tags:
                failed = True
                reason = "no tags"
        
        elif "vnet" in check_id and "ddos" in check_id:
            if row.get("enable_ddos_protection") != True:
                failed = True
                reason = "DDoS protection not enabled"
        
        elif "keyvault-logging" in check_id:
            diag = str(row.get("diagnostic_settings", ""))
            if not diag or diag == "None" or diag == "[]":
                failed = True
                reason = "no diagnostic logging configured"
        
        elif "storage-logging" in check_id:
            logging = str(row.get("blob_service_logging", ""))
            if not logging or logging == "None":
                failed = True
                reason = "blob service logging not configured"
        
        elif "guest-users" in check_id:
            pass  # if rows exist, guests exist — informational finding
        
        elif "conditional-access" in check_id and "policies" in check_id:
            pass  # if rows exist, policies exist — pass
        
        elif "service-principal" in check_id:
            pass  # informational — inventory
        
        elif "community-profile" in check_id and "readme" in check_id:
            if not row.get("readme"):
                failed = True
                reason = "no README file"
        
        elif "community-profile" in check_id and "contributing" in check_id:
            if not row.get("contributing"):
                failed = True
                reason = "no CONTRIBUTING guide"
        
        elif "community-profile" in check_id and "code-of-conduct" in check_id:
            if not row.get("code_of_conduct"):
                failed = True
                reason = "no code of conduct"
        
        elif "actions-workflow" in check_id:
            conclusion = row.get("conclusion", "")
            if conclusion == "failure":
                failed = True
                reason = f"workflow run failed on {row.get('head_branch', 'unknown')}"
        
        elif "codeowners" in check_id:
            pass  # if rows exist, CODEOWNERS exists — pass

        elif "ec2" in check_id and "imdsv2" in check_id:
            opts = str(row.get("metadata_options", ""))
            if "required" not in opts.lower():
                failed = True
                reason = "IMDSv2 not required"
        
        elif "ec2" in check_id and "public-ip" in check_id:
            if row.get("public_ip_address"):
                failed = True
                reason = f"has public IP {row.get('public_ip_address')}"
        
        elif "ec2" in check_id and "ssm" in check_id:
            if not row.get("iam_instance_profile_arn"):
                failed = True
                reason = "no IAM instance profile (needed for SSM)"
        
        elif "ec2" in check_id and "tagged" in check_id:
            if not row.get("tags"):
                failed = True
                reason = "no tags"
        
        elif "ec2" in check_id and "ebs-encrypted" in check_id:
            mappings = str(row.get("block_device_mappings", ""))
            if "false" in mappings.lower():
                failed = True
                reason = "instance has unencrypted EBS volumes"
        
        elif "ebs-volume" in check_id and "encryption" in check_id:
            if row.get("encrypted") != True:
                failed = True
                reason = "EBS volume not encrypted"
        
        elif "access-key-age" in check_id:
            from datetime import datetime, timezone
            created = str(row.get("create_date", ""))
            if created:
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - created_dt).days
                    if age_days > 90:
                        failed = True
                        reason = f"access key is {age_days} days old"
                except:
                    pass
        
        elif "policy-full-admin" in check_id:
            pass  # informational — inventory of custom policies
        
        elif "waf" in check_id and "web-acl" in check_id:
            pass  # if rows exist, WAF is configured — pass
        
        elif "waf" in check_id and "logging" in check_id:
            log_config = row.get("logging_configuration")
            if not log_config:
                failed = True
                reason = "WAF logging not configured"
        
        elif "kms" in check_id and "rotation-enabled" in check_id:
            if row.get("key_rotation_enabled") != True:
                failed = True
                reason = "KMS key rotation not enabled"
        
        elif "root-account-usage-alarm" in check_id:
            pass  # if rows exist, alarm exists — pass
        
        elif "password-policy" in check_id and "length" in check_id:
            min_len = row.get("minimum_password_length", 0)
            if min_len is None or min_len < 14:
                failed = True
                reason = f"minimum password length is {min_len} (should be >= 14)"
        
        elif "sql" in check_id and "tde" in check_id:
            tde = str(row.get("transparent_data_encryption", ""))
            if "Enabled" not in tde:
                failed = True
                reason = "TDE not enabled"
        
        elif "sql" in check_id and "auditing" in check_id:
            audit = str(row.get("audit_policy", ""))
            if "Enabled" not in audit:
                failed = True
                reason = "SQL auditing not enabled"
        
        elif "storage-firewall" in check_id:
            action = row.get("network_rule_default_action", "")
            if action != "Deny":
                failed = True
                reason = f"default network action is {action}, should be Deny"
        
        elif "keyvault" in check_id and "rbac" in check_id:
            if row.get("enable_rbac_authorization") != True:
                failed = True
                reason = "using access policies instead of RBAC"
        
        elif "global-admin-count" in check_id:
            pass  # informational — count matters, logged as finding for audit
        
        elif "entra-applications" in check_id:
            pass  # informational — inventory
        
        elif "nsg-flow-logs" in check_id:
            if not row.get("flow_log_id"):
                failed = True
                reason = "NSG flow logs not enabled"
        
        elif "actions-env-secrets" in check_id:
            pass  # if secrets exist, they're using environment secrets — pass
        
        elif "default-branch-main" in check_id:
            ref = str(row.get("default_branch_ref", ""))
            if "master" in ref.lower():
                failed = True
                reason = "default branch is 'master', should be 'main'"
        
        elif "repo-has-description" in check_id:
            if not row.get("description"):
                failed = True
                reason = "no repository description"
        
        elif "repo-has-topics" in check_id:
            topics = row.get("topics", [])
            if not topics:
                failed = True
                reason = "no topics set"

        elif "mfa-delete" in check_id:
            if row.get("mfa_delete") != "Enabled":
                failed = True
                reason = "MFA delete not enabled"
        
        elif "iam-user-count" in check_id:
            pass  # informational — inventory
        
        elif "kms-key-enabled" in check_id:
            state = row.get("key_state", "")
            if state != "Enabled":
                failed = True
                reason = f"KMS key state is {state}"
        
        elif "cloudtrail-multi-region" in check_id:
            if row.get("is_multi_region_trail") != True:
                failed = True
                reason = "CloudTrail not configured for multi-region"
        
        elif "keyvault-secret-expiry" in check_id:
            if not row.get("expires_at"):
                failed = True
                reason = "secret has no expiration date"
        
        elif "blob-versioning" in check_id:
            if row.get("blob_versioning_enabled") != True:
                failed = True
                reason = "blob versioning not enabled"
        
        elif "mfa-registration-details" in check_id:
            if row.get("is_mfa_registered") != True:
                failed = True
                reason = f"user {row.get('user_display_name', 'unknown')} has no MFA registered"
        
        elif "admin-consent-policy" in check_id:
            pass  # informational — existence check
        
        elif "archived" in check_id:
            failed = True
            reason = "repository is archived but may still be active"
        
        elif "restricts-pushes" in check_id:
            if row.get("restricts_pushes") != True:
                failed = True
                reason = "default branch does not restrict pushes"
        
        elif "repo-has-description" in check_id:
            if not row.get("description"):
                failed = True
                reason = "no repository description"
        
        elif "repo-has-topics" in check_id:
            topics = row.get("topics", [])
            if not topics:
                failed = True
                reason = "no topics set"
        
        if failed:
            findings["deny"].append(f"{severity}: {name} — {reason} ({desc})")
        else:
            findings["pass"].append(f"PASS: {name} — {desc}")
    
    return findings

def build_oscal(all_results, catalog):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    KSI_NS = "https://fedramp.gov/ns/oscal"

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
        # Build the props list for this result, including KSI references
        props = [
            {"name": "control-id", "value": result["control_id"]},
            {"name": "check-id", "value": result["check_id"]},
            {"name": "severity", "value": result["severity"]}
        ]
        # One prop per KSI — OSCAL convention for multi-valued metadata
        for ksi in result.get("fedramp_20x_ksi", []):
            props.append({
                "name": "fedramp-20x-ksi",
                "ns": KSI_NS,
                "value": ksi
            })

        r = {
            "uuid": str(uuid.uuid4()),
            "title": f"{result['check_id']} — {result['check_description']}",
            "description": result["check_description"],
            "start": now,
            "props": props,
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
    # NEW: accept one or many catalogs
    catalog_paths = sys.argv[1:] if len(sys.argv) > 1 else ["catalog/fedramp-moderate-aws.json"]

    # NEW: track combined coverage across all catalogs in this run
    combined_ksi_covered = set()
    combined_total_checks = 0
    combined_total_pass = 0
    combined_total_fail = 0
    combined_total_errors = 0
    output_files = []

    for catalog_path in catalog_paths:
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

                if len(denials) > 0:
                    print(f"    ✗ {check['check_id']}: {len(denials)} failed")
                elif len(passes) > 0:
                    print(f"    ✓ {check['check_id']}: {len(passes)} passed")

                total_pass += len(passes)
                total_fail += len(denials)

                # NEW: emit one result per check (not per control)
                all_results.append({
                    "control_id": control["control_id"],
                    "control_title": control["title"],
                    "check_id": check["check_id"],
                    "check_description": check.get("description", ""),
                    "severity": check.get("severity", "medium"),
                    "fedramp_20x_ksi": check.get("fedramp_20x_ksi", []),
                    "deny": denials,
                    "pass": passes
                })

        # NEW: per-catalog OSCAL output filename derived from provider
        oscal_ar = build_oscal(all_results, catalog)
        provider = catalog['provider'].lower()
        output_path = f"oscal/assessment-results-{provider}.json"
        with open(output_path, "w") as f:
            json.dump(oscal_ar, f, indent=2)
        output_files.append(output_path)

        # Per-catalog banner (existing)
        print()
        print("=" * 60)
        controls_checked = len(catalog["controls"])

        ksi_covered = set()
        for control in catalog["controls"]:
            for check in control.get("checks", []):
                for ksi in check.get("fedramp_20x_ksi", []):
                    ksi_covered.add(ksi)
        ksi_total = 61  # FedRAMP 20x Moderate total

        print(f"Controls scanned: {controls_checked}")
        print(f"Individual checks: {total_checks} ({total_errors} errors)")
        print(f"FedRAMP 20x KSI coverage: {len(ksi_covered)} of {ksi_total} Moderate KSIs")
        print(f"Results: {total_pass} passed, {total_fail} failed")
        print(f"OSCAL output: {output_path}")
        print("=" * 60)
        print()

        # NEW: aggregate into combined totals
        combined_ksi_covered.update(ksi_covered)
        combined_total_checks += total_checks
        combined_total_pass += total_pass
        combined_total_fail += total_fail
        combined_total_errors += total_errors

    # NEW: combined banner if more than one catalog scanned
    if len(catalog_paths) > 1:
        print("=" * 60)
        print(f"Combined coverage across {len(catalog_paths)} catalogs ({', '.join(p.split('/')[-1] for p in catalog_paths)})")
        print(f"Individual checks: {combined_total_checks} ({combined_total_errors} errors)")
        print(f"FedRAMP 20x KSI coverage: {len(combined_ksi_covered)} of 61 Moderate KSIs (union)")
        print(f"Results: {combined_total_pass} passed, {combined_total_fail} failed")
        print(f"OSCAL outputs: {', '.join(output_files)}")
        print("=" * 60)
        print()

if __name__ == "__main__":
    main()