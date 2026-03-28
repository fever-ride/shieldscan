variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

# Lambda invoke ARNs — all required now (no more count gating)
variable "sast_validator_invoke_arn" {
  type = string
}

variable "pentest_trigger_invoke_arn" {
  type = string
}

variable "query_invoke_arn" {
  type = string
}

# Cognito — required
variable "cognito_user_pool_endpoint" {
  type = string
}

variable "cognito_user_pool_client_id" {
  type = string
}

# Lambda function names (for permissions)
variable "sast_validator_function_name" {
  type = string
}

variable "pentest_trigger_function_name" {
  type = string
}

variable "query_function_name" {
  type = string
}