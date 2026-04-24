package openframp.iam

   deny contains msg if {
       some user in input.rows
       user.mfa_enabled == false
       msg := sprintf("FAIL: IAM user '%s' has no MFA enabled (FedRAMP IA-2, PCI DSS 8.3.1)", [user.name])
   }

   deny contains msg if {
       some user in input.rows
       user.password_last_used != null
       user.mfa_enabled == false
       msg := sprintf("CRITICAL: IAM user '%s' has console access without MFA (FedRAMP IA-2(1))", [user.name])
   }

   pass contains msg if {
       some user in input.rows
       user.mfa_enabled == true
       msg := sprintf("PASS: IAM user '%s' has MFA enabled", [user.name])
   }