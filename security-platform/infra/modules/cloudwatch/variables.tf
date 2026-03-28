variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

# SQS names (for CloudWatch alarm dimensions)
variable "sast_queue_name" {
  type = string
}

variable "pentest_queue_name" {
  type = string
}

variable "sast_dlq_name" {
  type = string
}

variable "pentest_dlq_name" {
  type = string
}

# Lambda function names
variable "sast_scanner_function_name" {
  type = string
}

variable "pentest_trigger_function_name" {
  type = string
}

# ECS names (for dashboard)
variable "ecs_cluster_name" {
  type = string
}

variable "pentest_worker_service_name" {
  type = string
}