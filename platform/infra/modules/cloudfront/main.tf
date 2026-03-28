# -----------------------------------------------------
# CloudFront Origin Access Identity
# -----------------------------------------------------

resource "aws_cloudfront_origin_access_identity" "frontend" {
  comment = "${var.project_name}-${var.environment}-frontend-oai"
}

# -----------------------------------------------------
# CloudFront Distribution
# -----------------------------------------------------

resource "aws_cloudfront_distribution" "frontend" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "${var.project_name}-${var.environment}-dashboard"

  # S3 origin — React SPA
  origin {
    domain_name = var.s3_bucket_regional_domain_name
    origin_id   = "s3-frontend"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.frontend.cloudfront_access_identity_path
    }
  }

  # Default cache behavior
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-frontend"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  # SPA routing — return index.html for 404s
  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = { Name = "${var.project_name}-${var.environment}-frontend" }
}

# Allow CloudFront OAI to read SPA assets from S3
resource "aws_s3_bucket_policy" "frontend" {
  bucket = var.s3_bucket_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudFrontOAIRead"
      Effect    = "Allow"
      Principal = { AWS = aws_cloudfront_origin_access_identity.frontend.iam_arn }
      Action    = "s3:GetObject"
      Resource  = "${var.s3_bucket_arn}/*"
    }]
  })
}