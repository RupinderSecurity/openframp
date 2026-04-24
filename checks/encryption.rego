package openframp.encryption

   deny contains msg if {
       some bucket in input.rows
       bucket.server_side_encryption_configuration == null
       msg := sprintf("FAIL: S3 bucket '%s' has no encryption configured (FedRAMP SC-28)", [bucket.name])
   }

   pass contains msg if {
       some bucket in input.rows
       bucket.server_side_encryption_configuration != null
       msg := sprintf("PASS: S3 bucket '%s' has encryption configured", [bucket.name])
   }