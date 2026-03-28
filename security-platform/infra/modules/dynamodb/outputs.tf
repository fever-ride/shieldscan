output "scans_table_name" {
  value = aws_dynamodb_table.scans.name
}

output "scans_table_arn" {
  value = aws_dynamodb_table.scans.arn
}

output "scan_targets_table_name" {
  value = aws_dynamodb_table.scan_targets.name
}

output "scan_targets_table_arn" {
  value = aws_dynamodb_table.scan_targets.arn
}