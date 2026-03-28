terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# =============================================================
# Phase 1 — Foundation
# =============================================================

module "vpc" {
  source       = "./modules/vpc"
  project_name = var.project_name
  environment  = var.environment
  vpc_cidr     = var.vpc_cidr
  az_count     = var.az_count
}

module "dynamodb" {
  source       = "./modules/dynamodb"
  project_name = var.project_name
  environment  = var.environment
}

module "s3_reports" {
  source       = "./modules/s3_reports"
  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region
}

module "sqs" {
  source       = "./modules/sqs"
  project_name = var.project_name
  environment  = var.environment
}

# =============================================================
# IAM — shared across all phases
# =============================================================

module "iam" {
  source       = "./modules/iam"
  project_name = var.project_name
  environment  = var.environment
  use_lab_role = var.use_lab_role

  sast_queue_arn         = module.sqs.sast_queue_arn
  pentest_queue_arn      = module.sqs.pentest_queue_arn
  scans_table_arn        = module.dynamodb.scans_table_arn
  scan_targets_table_arn = module.dynamodb.scan_targets_table_arn
  reports_bucket_arn     = module.s3_reports.bucket_arn
  sns_topic_arn          = module.sns.topic_arn
}

# =============================================================
# Phase 2 — SAST Pipeline
# =============================================================

module "api_gateway" {
  source       = "./modules/api_gateway"
  project_name = var.project_name
  environment  = var.environment

  sast_validator_invoke_arn   = module.lambda_sast.validator_invoke_arn
  pentest_trigger_invoke_arn  = module.lambda_pentest.invoke_arn
  query_invoke_arn            = module.lambda_query.invoke_arn
  cognito_user_pool_endpoint  = module.cognito.user_pool_endpoint
  cognito_user_pool_client_id = module.cognito.client_id

  # Function names for lambda_permission (centralized here to avoid circular deps)
  sast_validator_function_name  = module.lambda_sast.validator_function_name
  pentest_trigger_function_name = module.lambda_pentest.function_name
  query_function_name           = module.lambda_query.function_name
}

module "lambda_sast" {
  source       = "./modules/lambda_sast"
  project_name = var.project_name
  environment  = var.environment

  lambda_validator_role_arn = module.iam.lambda_validator_role_arn
  lambda_sast_role_arn      = module.iam.lambda_sast_role_arn

  sast_queue_url  = module.sqs.sast_queue_url
  sast_queue_arn  = module.sqs.sast_queue_arn

  scans_table_name    = module.dynamodb.scans_table_name
  reports_bucket_name = module.s3_reports.bucket_name
  sns_topic_arn       = module.sns.topic_arn

  github_webhook_secret = var.github_webhook_secret
  github_token          = var.github_token
}

# =============================================================
# Phase 3 — Pentest Pipeline
# =============================================================

module "lambda_pentest" {
  source       = "./modules/lambda_pentest"
  project_name = var.project_name
  environment  = var.environment

  lambda_pentest_role_arn    = module.iam.lambda_pentest_role_arn
  scan_targets_table_name   = module.dynamodb.scan_targets_table_name
  pentest_queue_url         = module.sqs.pentest_queue_url
}

module "ecs_fargate" {
  source       = "./modules/ecs_fargate"
  project_name = var.project_name
  environment  = var.environment

  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids

  ecs_execution_role_arn = module.iam.ecs_execution_role_arn
  ecs_task_role_arn      = module.iam.ecs_task_role_arn

  pentest_queue_url  = module.sqs.pentest_queue_url
  pentest_queue_name = "${var.project_name}-${var.environment}-pentest"
  scans_table_name   = module.dynamodb.scans_table_name
  reports_bucket_name = module.s3_reports.bucket_name
  sns_topic_arn      = module.sns.topic_arn
  enable_demo_target = var.enable_demo_target
}

# =============================================================
# Phase 4 — Dashboard (backend only, frontend skipped for now)
# =============================================================

module "lambda_query" {
  source       = "./modules/lambda_query"
  project_name = var.project_name
  environment  = var.environment

  lambda_query_role_arn     = module.iam.lambda_query_role_arn
  scans_table_name          = module.dynamodb.scans_table_name
  scan_targets_table_name   = module.dynamodb.scan_targets_table_name
  reports_bucket_name       = module.s3_reports.bucket_name
}

module "cognito" {
  source       = "./modules/cognito"
  project_name = var.project_name
  environment  = var.environment
  admin_email  = var.admin_email
}

module "s3_frontend" {
  count = var.enable_frontend_cdn ? 1 : 0
  source       = "./modules/s3_frontend"
  project_name = var.project_name
  environment  = var.environment
}

module "cloudfront" {
  count = var.enable_frontend_cdn ? 1 : 0
  source       = "./modules/cloudfront"
  project_name = var.project_name
  environment  = var.environment

  s3_bucket_name                 = module.s3_frontend[0].bucket_name
  s3_bucket_arn                  = module.s3_frontend[0].bucket_arn
  s3_bucket_regional_domain_name = module.s3_frontend[0].bucket_regional_domain_name
}

# =============================================================
# Phase 5 — Alerting & Monitoring
# =============================================================

module "sns" {
  source       = "./modules/sns"
  project_name = var.project_name
  environment  = var.environment
  alert_email  = var.alert_email
}

module "lambda_alert" {
  source       = "./modules/lambda_alert"
  project_name = var.project_name
  environment  = var.environment

  lambda_alert_role_arn = module.iam.lambda_alert_role_arn
  sns_topic_arn         = module.sns.topic_arn
}

module "cloudwatch" {
  source       = "./modules/cloudwatch"
  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  sns_topic_arn = module.sns.topic_arn

  sast_queue_name    = "${var.project_name}-${var.environment}-sast"
  pentest_queue_name = "${var.project_name}-${var.environment}-pentest"
  sast_dlq_name      = "${var.project_name}-${var.environment}-sast-dlq"
  pentest_dlq_name   = "${var.project_name}-${var.environment}-pentest-dlq"

  sast_scanner_function_name    = module.lambda_sast.scanner_function_name
  pentest_trigger_function_name = module.lambda_pentest.function_name

  ecs_cluster_name            = module.ecs_fargate.cluster_name
  pentest_worker_service_name = module.ecs_fargate.pentest_worker_service_name
}