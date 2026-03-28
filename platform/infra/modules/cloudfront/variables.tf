variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "s3_bucket_regional_domain_name" {
  description = "S3 frontend bucket regional domain name"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 frontend bucket name"
  type        = string
}

variable "s3_bucket_arn" {
  description = "S3 frontend bucket ARN"
  type        = string
}