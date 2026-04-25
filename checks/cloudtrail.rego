package openframp.cloudtrail

deny contains msg if {
    count(input.rows) == 0
    msg := "FAIL: No CloudTrail trail exists in this account (FedRAMP AU-2, PCI DSS 10.1)"
}

deny contains msg if {
    some trail in input.rows
    trail.is_logging == false
    msg := sprintf("FAIL: CloudTrail '%s' exists but is not logging (FedRAMP AU-2)", [trail.name])
}

deny contains msg if {
    some trail in input.rows
    trail.is_multi_region_trail == false
    msg := sprintf("FAIL: CloudTrail '%s' is not multi-region (FedRAMP AU-2)", [trail.name])
}

deny contains msg if {
    some trail in input.rows
    trail.log_file_validation_enabled == false
    msg := sprintf("FAIL: CloudTrail '%s' has no log file validation (FedRAMP AU-9)", [trail.name])
}

pass contains msg if {
    some trail in input.rows
    trail.is_logging == true
    trail.is_multi_region_trail == true
    trail.log_file_validation_enabled == true
    msg := sprintf("PASS: CloudTrail '%s' is logging, multi-region, with validation enabled", [trail.name])
}