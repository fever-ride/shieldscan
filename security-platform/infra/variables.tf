variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "securityplatform"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to use"
  type        = number
  default     = 2
}

variable "enable_frontend_cdn" {
  description = "Create s3_frontend + CloudFront resources"
  type        = bool
  default     = false
}

variable "enable_demo_target" {
  description = "Create demo test-target and Service Discovery resources in ECS module"
  type        = bool
  default     = false
}

# -----------------------------------------------------
# Learner Lab
# -----------------------------------------------------

variable "use_lab_role" {
  description = "Use pre-existing LabRole instead of creating IAM roles"
  type        = bool
  default     = true
}

# -----------------------------------------------------
# Secrets
# -----------------------------------------------------

variable "github_webhook_secret" {
  description = "GitHub webhook secret for HMAC verification"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_token" {
  description = "GitHub personal access token for cloning repos"
  type        = string
  sensitive   = true
  default     = ""
}

# -----------------------------------------------------
# Cognito
# -----------------------------------------------------

variable "admin_email" {
  description = "Admin user email for Cognito"
  type        = string
  default     = ""
}

# -----------------------------------------------------
# Alerting
# -----------------------------------------------------

variable "alert_email" {
  description = "Email address for SNS alert notifications"
  type        = string
  default     = ""
}