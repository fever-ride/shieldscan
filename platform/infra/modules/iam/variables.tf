variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "use_lab_role" {
  type    = bool
  default = true
}

variable "sast_queue_arn" {
  type = string
}

variable "pentest_queue_arn" {
  type = string
}

variable "scans_table_arn" {
  type = string
}

variable "scan_targets_table_arn" {
  type = string
}

variable "reports_bucket_arn" {
  type = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN — pass empty string if not yet created"
  type        = string
  default     = ""
}