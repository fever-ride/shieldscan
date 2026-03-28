# -----------------------------------------------------
# S3 Bucket — React SPA static files (served via CloudFront)
# -----------------------------------------------------

resource "aws_s3_bucket" "frontend" {
  bucket = "${var.project_name}-${var.environment}-frontend-${data.aws_caller_identity.current.account_id}"

  tags = { Name = "${var.project_name}-${var.environment}-frontend" }
}

# Block all public access — CloudFront uses OAI to read
resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Website configuration (for SPA routing — index.html as error page)
resource "aws_s3_bucket_website_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

data "aws_caller_identity" "current" {}