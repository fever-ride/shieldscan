data "archive_file" "query" {
  type        = "zip"
  source_dir  = "${path.module}/src/query"
  output_path = "${path.module}/query.zip"
}

resource "aws_lambda_function" "query" {
  function_name = "${var.project_name}-${var.environment}-query-api"
  role          = var.lambda_query_role_arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.query.output_path
  source_code_hash = data.archive_file.query.output_base64sha256

  environment {
    variables = {
      SCANS_TABLE_NAME        = var.scans_table_name
      SCAN_TARGETS_TABLE_NAME = var.scan_targets_table_name
      REPORTS_BUCKET_NAME     = var.reports_bucket_name
    }
  }

  tags = { Name = "${var.project_name}-${var.environment}-query-api" }
}

resource "aws_cloudwatch_log_group" "query" {
  name              = "/aws/lambda/${aws_lambda_function.query.function_name}"
  retention_in_days = 14
}