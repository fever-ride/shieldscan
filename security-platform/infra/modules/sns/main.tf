# -----------------------------------------------------
# SNS Topic — all alerts (scan findings + system alarms)
# -----------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-${var.environment}-alerts"

  tags = { Name = "${var.project_name}-${var.environment}-alerts" }
}

# -----------------------------------------------------
# Email Subscription
# -----------------------------------------------------

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# -----------------------------------------------------
# Lambda Subscription (alert function processes and forwards)
# -----------------------------------------------------

resource "aws_sns_topic_subscription" "alert_lambda" {
  count     = var.alert_lambda_arn != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "lambda"
  endpoint  = var.alert_lambda_arn
}