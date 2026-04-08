output "scans_table_name" {
  value = aws_dynamodb_table.scans.name
}

output "scans_table_arn" {
  value = aws_dynamodb_table.scans.arn
}

output "apps_table_name" {
  value = aws_dynamodb_table.apps.name
}

output "apps_table_arn" {
  value = aws_dynamodb_table.apps.arn
}

output "ai_feedback_table_name" {
  value = aws_dynamodb_table.ai_feedback.name
}

output "ai_feedback_table_arn" {
  value = aws_dynamodb_table.ai_feedback.arn
}
