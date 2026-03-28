# -----------------------------------------------------
# S3 Bucket — scan reports (JSON/HTML/PDF)
# -----------------------------------------------------

resource "aws_s3_bucket" "reports" {
  bucket = "${var.project_name}-${var.environment}-reports-${data.aws_caller_identity.current.account_id}-${var.aws_region}"

  tags = {
    Name = "${var.project_name}-${var.environment}-reports"
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning (recover from accidental deletes)
resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------------------------------
# Lifecycle: transition to Glacier Deep Archive after 90 days
# -----------------------------------------------------

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "archive-old-reports"
    status = "Enabled"
    filter {}

    transition {
      days          = 90
      storage_class = "DEEP_ARCHIVE"
    }

    # Delete very old reports after 365 days (optional)
    expiration {
      days = 365
    }
  }
}

data "aws_caller_identity" "current" {}