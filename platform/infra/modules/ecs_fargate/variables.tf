variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "ecs_execution_role_arn" {
  type = string
}

variable "ecs_task_role_arn" {
  type = string
}

variable "pentest_queue_url" {
  type = string
}

variable "pentest_queue_name" {
  description = "SQS queue name (for CloudWatch alarm dimension)"
  type        = string
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

variable "enable_demo_target" {
  description = "Deploy demo vulnerable target and related Service Discovery resources"
  type        = bool
  default     = false
}