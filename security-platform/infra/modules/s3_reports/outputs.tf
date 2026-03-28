output "bucket_name" {
  value = aws_s3_bucket.reports.id
}

output "bucket_arn" {
  value = aws_s3_bucket.reports.arn
}