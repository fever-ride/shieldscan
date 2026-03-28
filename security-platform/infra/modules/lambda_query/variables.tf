variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "lambda_query_role_arn" {
  type = string
}

variable "scans_table_name" {
  type = string
}

variable "scan_targets_table_name" {
  type = string
}

variable "reports_bucket_name" {
  type = string
}