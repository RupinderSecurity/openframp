package openframp.s3

deny contains msg if {
    some bucket in input.rows
    bucket.block_public_acls == false
    msg := sprintf("FAIL: %s - public ACLs not blocked (FedRAMP AC-3, PCI DSS 1.3)", [bucket.name])
}

deny contains msg if {
    some bucket in input.rows
    bucket.block_public_policy == false
    msg := sprintf("FAIL: %s - public policy not blocked (FedRAMP AC-3)", [bucket.name])
}

deny contains msg if {
    some bucket in input.rows
    bucket.restrict_public_buckets == false
    msg := sprintf("FAIL: %s - public buckets not restricted (FedRAMP AC-3)", [bucket.name])
}

pass contains msg if {
    some bucket in input.rows
    bucket.block_public_acls == true
    bucket.block_public_policy == true
    bucket.restrict_public_buckets == true
    msg := sprintf("PASS: %s - all public access controls enabled", [bucket.name])
}