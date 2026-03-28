data "archive_file" "alert" {
  type        = "zip"
  source_dir  = "${path.module}/src/alert"
  output_path = "${path.module}/alert.zip"
}

resource "aws_lambda_function" "alert" {
  function_name = "${var.project_name}-${var.environment}-alert"
  role          = var.lambda_alert_role_arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 30
  memory_size   = 128

  filename         = data.archive_file.alert.output_path
  source_code_hash = data.archive_file.alert.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = var.sns_topic_arn
    }
  }

  tags = { Name = "${var.project_name}-${var.environment}-alert" }
}

resource "aws_cloudwatch_log_group" "alert" {
  name              = "/aws/lambda/${aws_lambda_function.alert.function_name}"
  retention_in_days = 14
}

# Permission: SNS can invoke this Lambda (for CloudWatch Alarm → SNS → Lambda pattern)
resource "aws_lambda_permission" "alert_sns" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = var.sns_topic_arn
}