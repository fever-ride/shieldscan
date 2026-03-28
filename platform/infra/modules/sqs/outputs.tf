output "sast_queue_url" {
  value = aws_sqs_queue.sast.url
}

output "sast_queue_arn" {
  value = aws_sqs_queue.sast.arn
}

output "sast_dlq_arn" {
  value = aws_sqs_queue.sast_dlq.arn
}

output "pentest_queue_url" {
  value = aws_sqs_queue.pentest.url
}

output "pentest_queue_arn" {
  value = aws_sqs_queue.pentest.arn
}

output "pentest_dlq_arn" {
  value = aws_sqs_queue.pentest_dlq.arn
}