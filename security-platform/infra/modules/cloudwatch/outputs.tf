output "dashboard_name" {
  value = aws_cloudwatch_dashboard.main.dashboard_name
}

output "sast_dlq_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.sast_dlq.arn
}

output "pentest_dlq_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.pentest_dlq.arn
}