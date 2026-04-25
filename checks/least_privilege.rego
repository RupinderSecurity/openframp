package openframp.leastprivilege

deny contains msg if {
    some user in input.rows
    user.attached_policy_arns != null
    contains(user.attached_policy_arns, "AdministratorAccess")
    msg := sprintf("CRITICAL: IAM user '%s' has AdministratorAccess attached (FedRAMP AC-6, PCI DSS 7.1)", [user.name])
}

deny contains msg if {
    some user in input.rows
    user.attached_policy_arns != null
    contains(user.attached_policy_arns, "PowerUserAccess")
    msg := sprintf("FAIL: IAM user '%s' has PowerUserAccess attached (FedRAMP AC-6)", [user.name])
}

pass contains msg if {
    some user in input.rows
    not contains(user.attached_policy_arns, "AdministratorAccess")
    not contains(user.attached_policy_arns, "PowerUserAccess")
    msg := sprintf("PASS: IAM user '%s' does not have overly broad policies", [user.name])
}