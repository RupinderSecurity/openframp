# Get the current account ID so the trust policy is portable
data "aws_caller_identity" "current" {}

# The scanner role — replaces the scanner IAM user
# Anyone in the same account can assume this role
# In production, you'd restrict this to specific users or services
resource "aws_iam_role" "scanner" {
  name = "openframp-scanner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalType" = "User"
          }
        }
      }
    ]
  })

  tags = {
    Project = "openframp"
    Purpose = "read-only-compliance-scanner"
    Managed = "opentofu"
  }
}

# Same SecurityAudit policy as the user-based module
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}