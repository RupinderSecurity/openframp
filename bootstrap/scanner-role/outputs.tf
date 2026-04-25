output "scanner_role_arn" {
  description = "ARN of the scanner role. Use this in Steampipe config and AWS CLI profiles."
  value       = aws_iam_role.scanner.arn
}

output "scanner_role_name" {
  description = "Name of the scanner role."
  value       = aws_iam_role.scanner.name
}

output "steampipe_config" {
  description = "Paste this into ~/.steampipe/config/aws.spc"
  value       = <<-EOT
    connection "aws" {
      plugin   = "aws"
      role_arn = "${aws_iam_role.scanner.arn}"
      regions  = ["us-west-2"]
    }
  EOT
}