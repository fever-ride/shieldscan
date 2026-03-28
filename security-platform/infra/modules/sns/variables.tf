variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "alert_email" {
  description = "Email address for alert notifications (leave empty to skip)"
  type        = string
  default     = ""
}

variable "alert_lambda_arn" {
  description = "Alert Lambda ARN for SNS subscription (leave empty to skip)"
  type        = string
  default     = ""
}