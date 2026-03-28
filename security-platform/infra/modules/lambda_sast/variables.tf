variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "lambda_validator_role_arn" {
  type = string
}

variable "lambda_sast_role_arn" {
  type = string
}

variable "sast_queue_url" {
  type = string
}

variable "sast_queue_arn" {
  type = string
}

variable "scans_table_name" {
  type = string
}

variable "reports_bucket_name" {
  type = string
}

variable "sns_topic_arn" {
  type    = string
  default = ""
}

variable "github_webhook_secret" {
  type      = string
  sensitive = true
}

variable "github_token" {
  type      = string
  sensitive = true
}