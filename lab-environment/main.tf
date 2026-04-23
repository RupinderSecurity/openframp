resource "random_id" "suffix" {
  byte_length = 4
}

# Insecure S3 bucket - public access allowed (violates FedRAMP AC-3, PCI DSS 1.3)
resource "aws_s3_bucket" "insecure" {
  bucket = "openframp-test-insecure-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "insecure" {
  bucket                  = aws_s3_bucket.insecure.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Secure S3 bucket - public access blocked, encryption on (passes FedRAMP AC-3, SC-28)
resource "aws_s3_bucket" "secure" {
  bucket = "openframp-test-secure-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}