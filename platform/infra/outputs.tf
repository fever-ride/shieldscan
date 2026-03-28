# -----------------------------------------------------
# API
# -----------------------------------------------------

output "api_endpoint" {
  description = "API Gateway URL — use this as your webhook URL"
  value       = module.api_gateway.api_endpoint
}

# -----------------------------------------------------
# ECS / Docker
# -----------------------------------------------------

output "pentest_worker_ecr_url" {
  description = "ECR URL — push pentest-worker Docker image here"
  value       = module.ecs_fargate.pentest_worker_ecr_url
}

output "test_target_ecr_url" {
  description = "ECR URL — push test-target Docker image here"
  value       = module.ecs_fargate.test_target_ecr_url
}

output "test_target_dns" {
  description = "Internal DNS for test-target (use as pentest target URL)"
  value       = "http://${module.ecs_fargate.test_target_dns}:4000"
}

# -----------------------------------------------------
# Cognito
# -----------------------------------------------------

output "cognito_user_pool_id" {
  value = module.cognito.user_pool_id
}

output "cognito_client_id" {
  value = module.cognito.client_id
}

# -----------------------------------------------------
# Storage
# -----------------------------------------------------

output "scans_table_name" {
  value = module.dynamodb.scans_table_name
}

output "reports_bucket_name" {
  value = module.s3_reports.bucket_name
}

output "frontend_bucket_name" {
  description = "S3 bucket for frontend static assets"
  value       = var.enable_frontend_cdn ? module.s3_frontend[0].bucket_name : ""
}

output "frontend_url" {
  description = "CloudFront URL for dashboard frontend"
  value       = var.enable_frontend_cdn ? "https://${module.cloudfront[0].distribution_domain_name}" : ""
}

# -----------------------------------------------------
# Monitoring
# -----------------------------------------------------

output "cloudwatch_dashboard_url" {
  value = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${module.cloudwatch.dashboard_name}"
}