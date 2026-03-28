# -----------------------------------------------------
# SAST Dead Letter Queue
# -----------------------------------------------------

resource "aws_sqs_queue" "sast_dlq" {
  name                      = "${var.project_name}-${var.environment}-sast-dlq"
  message_retention_seconds = 1209600 # 14 days — max retention for failed messages

  tags = {
    Name = "${var.project_name}-${var.environment}-sast-dlq"
  }
}

# -----------------------------------------------------
# SAST Queue
# -----------------------------------------------------

resource "aws_sqs_queue" "sast" {
  name                       = "${var.project_name}-${var.environment}-sast"
  visibility_timeout_seconds = 300 # 5 min — must be > Lambda timeout
  message_retention_seconds  = 86400 # 1 day
  receive_wait_time_seconds  = 20 # Long polling — reduces empty receives

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.sast_dlq.arn
    maxReceiveCount     = 3 # After 3 failures → DLQ
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-sast"
  }
}

# -----------------------------------------------------
# Pentest Dead Letter Queue
# -----------------------------------------------------

resource "aws_sqs_queue" "pentest_dlq" {
  name                      = "${var.project_name}-${var.environment}-pentest-dlq"
  message_retention_seconds = 1209600

  tags = {
    Name = "${var.project_name}-${var.environment}-pentest-dlq"
  }
}

# -----------------------------------------------------
# Pentest Queue
# -----------------------------------------------------

resource "aws_sqs_queue" "pentest" {
  name                       = "${var.project_name}-${var.environment}-pentest"
  visibility_timeout_seconds = 600 # 10 min — pentests take longer
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.pentest_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-pentest"
  }
}