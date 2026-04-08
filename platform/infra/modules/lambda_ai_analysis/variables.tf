variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "lambda_ai_role_arn" {
  type = string
}

variable "sast_complete_topic_arn" {
  type = string
}

variable "scans_table_name" {
  type = string
}

variable "reports_bucket_name" {
  type = string
}

variable "ai_feedback_table_name" {
  type    = string
  default = ""
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
}

variable "ai_analysis_enabled" {
  type    = string
  default = "false"
}

variable "github_token" {
  type      = string
  sensitive = true
  default   = ""
}
