output "distribution_domain_name" {
  value = aws_cloudfront_distribution.frontend.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.frontend.id
}

output "oai_arn" {
  value = aws_cloudfront_origin_access_identity.frontend.iam_arn
}