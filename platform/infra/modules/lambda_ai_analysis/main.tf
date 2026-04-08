# -----------------------------------------------------
# Lambda: AI Analysis (SNS → triage SAST findings)
# -----------------------------------------------------

data "archive_file" "ai_analysis" {
  type        = "zip"
  source_dir  = "${path.module}/src/analysis"
  output_path = "${path.module}/ai_analysis.zip"
}

resource "aws_lambda_function" "ai_analysis" {
  function_name = "${var.project_name}-${var.environment}-ai-analysis"
  role          = var.lambda_ai_role_arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 300
  memory_size   = 256

  filename         = data.archive_file.ai_analysis.output_path
  source_code_hash = data.archive_file.ai_analysis.output_base64sha256

  environment {
    variables = {
      SCANS_TABLE_NAME       = var.scans_table_name
      REPORTS_BUCKET_NAME    = var.reports_bucket_name
      AI_FEEDBACK_TABLE_NAME = var.ai_feedback_table_name
      ANTHROPIC_API_KEY      = var.anthropic_api_key
      AI_ANALYSIS_ENABLED    = var.ai_analysis_enabled
      GITHUB_TOKEN           = var.github_token
    }
  }

  tags = { Name = "${var.project_name}-${var.environment}-ai-analysis" }
}

resource "aws_cloudwatch_log_group" "ai_analysis" {
  name              = "/aws/lambda/${aws_lambda_function.ai_analysis.function_name}"
  retention_in_days = 14
}

# -----------------------------------------------------
# SNS → Lambda subscription (sast_complete topic)
# -----------------------------------------------------

resource "aws_lambda_permission" "sns_invoke" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ai_analysis.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = var.sast_complete_topic_arn
}

resource "aws_sns_topic_subscription" "sast_complete" {
  topic_arn = var.sast_complete_topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.ai_analysis.arn
}
