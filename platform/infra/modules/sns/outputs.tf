output "topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "topic_name" {
  value = aws_sns_topic.alerts.name
}

output "sast_complete_topic_arn" {
  value = aws_sns_topic.sast_complete.arn
}