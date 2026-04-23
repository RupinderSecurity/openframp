# After tofu apply runs, these let you retrieve the scanner's credentials

output "scanner_access_key_id" {
  description = "The scanner's access key ID"
  value       = aws_iam_access_key.scanner.id
}

output "scanner_secret_access_key" {
  description = "The scanner's secret key - treat like a password"
  value       = aws_iam_access_key.scanner.secret
  sensitive   = true
}