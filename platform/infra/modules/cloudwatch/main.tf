# -----------------------------------------------------
# CloudWatch Alarms — DLQ monitoring
# -----------------------------------------------------

# Alarm: SAST DLQ has messages (scan failures)
resource "aws_cloudwatch_metric_alarm" "sast_dlq" {
  alarm_name          = "${var.project_name}-${var.environment}-sast-dlq-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "SAST Dead Letter Queue has failed messages"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    QueueName = var.sast_dlq_name
  }
}

# Alarm: Pentest DLQ has messages (scan failures)
resource "aws_cloudwatch_metric_alarm" "pentest_dlq" {
  alarm_name          = "${var.project_name}-${var.environment}-pentest-dlq-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Pentest Dead Letter Queue has failed messages"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    QueueName = var.pentest_dlq_name
  }
}

# -----------------------------------------------------
# CloudWatch Alarms — Lambda errors
# -----------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "sast_scanner_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-sast-scanner-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "SAST Scanner Lambda has 3+ errors in 5 minutes"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = var.sast_scanner_function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "pentest_trigger_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-pentest-trigger-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "Pentest Trigger Lambda has 3+ errors in 5 minutes"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    FunctionName = var.pentest_trigger_function_name
  }
}

# -----------------------------------------------------
# CloudWatch Alarm — HIGH findings spike (custom EMF metric)
# -----------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "high_findings_spike" {
  alarm_name          = "${var.project_name}-${var.environment}-high-findings-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "findings_total"
  namespace           = "ShieldScan"
  period              = 3600
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "More than 10 HIGH findings detected in the last hour"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    severity = "HIGH"
  }
}

# -----------------------------------------------------
# CloudWatch Dashboard — system overview
# -----------------------------------------------------

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-${var.environment}-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0, y = 0, width = 12, height = 6
        properties = {
          title   = "SQS Queue Depth"
          region  = var.aws_region
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.sast_queue_name],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.pentest_queue_name]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12, y = 0, width = 12, height = 6
        properties = {
          title   = "DLQ Messages (Failures)"
          region  = var.aws_region
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.sast_dlq_name],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.pentest_dlq_name]
          ]
          period = 60
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0, y = 6, width = 12, height = 6
        properties = {
          title   = "Lambda Invocations"
          region  = var.aws_region
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", var.sast_scanner_function_name],
            ["AWS/Lambda", "Invocations", "FunctionName", var.pentest_trigger_function_name]
          ]
          period = 300
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 12, y = 6, width = 12, height = 6
        properties = {
          title   = "Lambda Errors"
          region  = var.aws_region
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", var.sast_scanner_function_name],
            ["AWS/Lambda", "Errors", "FunctionName", var.pentest_trigger_function_name]
          ]
          period = 300
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0, y = 12, width = 24, height = 6
        properties = {
          title   = "ECS Fargate Running Tasks"
          region  = var.aws_region
          metrics = [
            ["AWS/ECS", "RunningTaskCount", "ClusterName", var.ecs_cluster_name, "ServiceName", var.pentest_worker_service_name]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0, y = 18, width = 12, height = 6
        properties = {
          title   = "Scans Completed (ShieldScan)"
          region  = var.aws_region
          metrics = [
            ["ShieldScan", "scans_total", "scan_type", "sast",    "status", "completed", { label = "SAST" }],
            ["ShieldScan", "scans_total", "scan_type", "pentest", "status", "completed", { label = "Pentest" }]
          ]
          period = 3600
          stat   = "Sum"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12, y = 18, width = 12, height = 6
        properties = {
          title   = "Findings by Severity (ShieldScan)"
          region  = var.aws_region
          metrics = [
            ["ShieldScan", "findings_total", "severity", "HIGH",   { label = "HIGH" }],
            ["ShieldScan", "findings_total", "severity", "MEDIUM", { label = "MEDIUM" }],
            ["ShieldScan", "findings_total", "severity", "LOW",    { label = "LOW" }]
          ]
          period = 3600
          stat   = "Sum"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 0, y = 24, width = 12, height = 6
        properties = {
          title   = "AI Triage + Agent Investigations"
          region  = var.aws_region
          metrics = [
            ["ShieldScan", "ai_triage_total",             "status", "success",              { label = "Triage OK" }],
            ["ShieldScan", "agent_investigations_total",   "verdict", "CONFIRMED",           { label = "Confirmed" }],
            ["ShieldScan", "agent_investigations_total",   "verdict", "LIKELY_FALSE_POSITIVE", { label = "False Positive" }]
          ]
          period = 3600
          stat   = "Sum"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12, y = 24, width = 12, height = 6
        properties = {
          title   = "Human Feedback (Confirm vs Dismiss)"
          region  = var.aws_region
          metrics = [
            ["ShieldScan", "human_feedback_total", "action", "confirm", { label = "Confirmed" }],
            ["ShieldScan", "human_feedback_total", "action", "dismiss", { label = "Dismissed" }]
          ]
          period = 3600
          stat   = "Sum"
          view   = "timeSeries"
        }
      }
    ]
  })
}