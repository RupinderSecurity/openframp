package openframp.securitygroups

deny contains msg if {
    some sg in input.rows
    sg.from_port == 0
    sg.to_port == 65535
    sg.cidr_ipv4 == "0.0.0.0/0"
    msg := sprintf("CRITICAL: Security group '%s' allows all ports from 0.0.0.0/0 (FedRAMP SC-7, PCI DSS 1.2.1)", [sg.group_id])
}

deny contains msg if {
    some sg in input.rows
    sg.from_port == 22
    sg.cidr_ipv4 == "0.0.0.0/0"
    msg := sprintf("FAIL: Security group '%s' allows SSH (port 22) from 0.0.0.0/0 (FedRAMP SC-7)", [sg.group_id])
}

deny contains msg if {
    some sg in input.rows
    sg.from_port == 3389
    sg.cidr_ipv4 == "0.0.0.0/0"
    msg := sprintf("FAIL: Security group '%s' allows RDP (port 3389) from 0.0.0.0/0 (FedRAMP SC-7)", [sg.group_id])
}

pass contains msg if {
    some sg in input.rows
    sg.cidr_ipv4 != "0.0.0.0/0"
    msg := sprintf("PASS: Security group rule '%s' is not open to the internet", [sg.group_id])
}