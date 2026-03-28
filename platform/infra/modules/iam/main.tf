# -----------------------------------------------------
# Learner Lab toggle:
#   use_lab_role = true  → use pre-existing LabRole
#   use_lab_role = false → create least-privilege roles
# -----------------------------------------------------

data "aws_iam_role" "lab_role" {
  count = var.use_lab_role ? 1 : 0
  name  = "LabRole"
}

# -----------------------------------------------------
# Lambda Validator Role (minimal — just push to SQS)
# -----------------------------------------------------

resource "aws_iam_role" "lambda_validator" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-validator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_validator" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-validator-policy"
  role  = aws_iam_role.lambda_validator[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SQSSendSAST"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = var.sast_queue_arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# -----------------------------------------------------
# Lambda SAST Scanner Role
# -----------------------------------------------------

resource "aws_iam_role" "lambda_sast" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-sast-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_sast" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-sast-policy"
  role  = aws_iam_role.lambda_sast[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SQSReadSAST"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = var.sast_queue_arn
      },
      {
        Sid      = "DynamoDBWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = var.scans_table_arn
      },
      {
        Sid      = "S3WriteReports"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# -----------------------------------------------------
# Lambda Pentest Trigger Role
# -----------------------------------------------------

resource "aws_iam_role" "lambda_pentest" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-pentest-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_pentest" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-pentest-policy"
  role  = aws_iam_role.lambda_pentest[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SQSSendPentest"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = var.pentest_queue_arn
      },
      {
        Sid      = "DynamoDBReadTargets"
        Effect   = "Allow"
        Action   = ["dynamodb:Scan", "dynamodb:Query"]
        Resource = [var.scan_targets_table_arn, "${var.scan_targets_table_arn}/index/*"]
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# -----------------------------------------------------
# Lambda Query API Role
# -----------------------------------------------------

resource "aws_iam_role" "lambda_query" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-query-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_query" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-query-policy"
  role  = aws_iam_role.lambda_query[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDBRead"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
        Resource = [
          var.scans_table_arn, "${var.scans_table_arn}/index/*",
          var.scan_targets_table_arn, "${var.scan_targets_table_arn}/index/*"
        ]
      },
      {
        Sid      = "DynamoDBWriteTargets"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
        Resource = var.scan_targets_table_arn
      },
      {
        Sid      = "S3ReadReports"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# -----------------------------------------------------
# Lambda Alert Role
# -----------------------------------------------------

resource "aws_iam_role" "lambda_alert" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-alert-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_alert" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-lambda-alert-policy"
  role  = aws_iam_role.lambda_alert[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# -----------------------------------------------------
# ECS Fargate Task Execution Role + Task Role
# -----------------------------------------------------

resource "aws_iam_role" "ecs_execution" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  count      = var.use_lab_role ? 0 : 1
  role       = aws_iam_role.ecs_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_task" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ecs_task" {
  count = var.use_lab_role ? 0 : 1
  name  = "${var.project_name}-${var.environment}-ecs-task-policy"
  role  = aws_iam_role.ecs_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SQSReadPentest"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = var.pentest_queue_arn
      },
      {
        Sid      = "DynamoDBWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = var.scans_table_arn
      },
      {
        Sid      = "S3WriteReports"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      }
    ]
  })
}