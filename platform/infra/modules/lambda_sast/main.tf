# -----------------------------------------------------
# Lambda: Webhook Validator
# -----------------------------------------------------

data "archive_file" "validator" {
  type        = "zip"
  source_dir  = "${path.module}/src/validator"
  output_path = "${path.module}/validator.zip"
}

resource "aws_lambda_function" "validator" {
  function_name = "${var.project_name}-${var.environment}-sast-validator"
  role          = var.lambda_validator_role_arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 30
  memory_size   = 128

  filename         = data.archive_file.validator.output_path
  source_code_hash = data.archive_file.validator.output_base64sha256

  environment {
    variables = {
      SAST_QUEUE_URL        = var.sast_queue_url
      GITHUB_WEBHOOK_SECRET = var.github_webhook_secret
    }
  }

  tags = { Name = "${var.project_name}-${var.environment}-sast-validator" }
}

resource "aws_cloudwatch_log_group" "validator" {
  name              = "/aws/lambda/${aws_lambda_function.validator.function_name}"
  retention_in_days = 14
}

# -----------------------------------------------------
# Lambda: SAST Scanner
# -----------------------------------------------------

data "archive_file" "scanner" {
  type        = "zip"
  source_dir  = "${path.module}/src/scanner"
  output_path = "${path.module}/scanner.zip"
}

resource "aws_lambda_function" "scanner" {
  function_name = "${var.project_name}-${var.environment}-sast-scanner"
  role          = var.lambda_sast_role_arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 120
  memory_size   = 512

  reserved_concurrent_executions = 50

  filename         = data.archive_file.scanner.output_path
  source_code_hash = data.archive_file.scanner.output_base64sha256

  environment {
    variables = {
      SCANS_TABLE_NAME    = var.scans_table_name
      REPORTS_BUCKET_NAME = var.reports_bucket_name
      SNS_TOPIC_ARN       = var.sns_topic_arn
      GITHUB_TOKEN        = var.github_token
    }
  }

  tags = { Name = "${var.project_name}-${var.environment}-sast-scanner" }
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${aws_lambda_function.scanner.function_name}"
  retention_in_days = 14
}

# -----------------------------------------------------
# SQS Event Source Mapping: SQS → Scanner Lambda
# -----------------------------------------------------

resource "aws_lambda_event_source_mapping" "sast_queue" {
  event_source_arn                   = var.sast_queue_arn
  function_name                      = aws_lambda_function.scanner.arn
  batch_size                         = 1
  maximum_batching_window_in_seconds = 0
  enabled                            = true

  scaling_config {
    maximum_concurrency = 50
  }
}