# This creates a read-only scanner user in AWS.
# Same idea as the Vanta auditor role we looked at on Wednesday:
# - Create a user
# - Attach the SecurityAudit policy (read-only access to everything)
# - Generate an access key so the scanner can log in

resource "aws_iam_user" "scanner" {
  name = "openframp-scanner"
  tags = {
    Project = "openframp"
    Purpose = "read-only-compliance-scanner"
  }
}

resource "aws_iam_user_policy_attachment" "security_audit" {
  user       = aws_iam_user.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_access_key" "scanner" {
  user = aws_iam_user.scanner.name
}