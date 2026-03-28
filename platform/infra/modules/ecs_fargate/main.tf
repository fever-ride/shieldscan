# -----------------------------------------------------
# ECR Repository — stores pentest worker Docker image
# -----------------------------------------------------

resource "aws_ecr_repository" "pentest_worker" {
  name                 = "${var.project_name}-${var.environment}-pentest-worker"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { Name = "${var.project_name}-${var.environment}-pentest-worker" }
}

resource "aws_ecr_repository" "test_target" {
  count                = var.enable_demo_target ? 1 : 0
  name                 = "${var.project_name}-${var.environment}-test-target"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  tags = { Name = "${var.project_name}-${var.environment}-test-target" }
}

# -----------------------------------------------------
# ECS Cluster
# -----------------------------------------------------

resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-${var.environment}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Name = "${var.project_name}-${var.environment}-cluster" }
}

# -----------------------------------------------------
# Security Group — Fargate tasks
# -----------------------------------------------------

resource "aws_security_group" "fargate" {
  name_prefix = "${var.project_name}-${var.environment}-fargate-"
  vpc_id      = var.vpc_id

  # Outbound: allow all (pentest needs to reach target APIs + AWS services)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-${var.environment}-fargate-sg" }
}

# Security group for test-target (allow inbound from Fargate workers)
resource "aws_security_group" "test_target" {
  count       = var.enable_demo_target ? 1 : 0
  name_prefix = "${var.project_name}-${var.environment}-test-target-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 4000
    to_port         = 4000
    protocol        = "tcp"
    security_groups = [aws_security_group.fargate.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-${var.environment}-test-target-sg" }
}

# -----------------------------------------------------
# CloudWatch Log Groups
# -----------------------------------------------------

resource "aws_cloudwatch_log_group" "pentest_worker" {
  name              = "/ecs/${var.project_name}-${var.environment}-pentest-worker"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "test_target" {
  count             = var.enable_demo_target ? 1 : 0
  name              = "/ecs/${var.project_name}-${var.environment}-test-target"
  retention_in_days = 14
}

# -----------------------------------------------------
# Task Definition — Pentest Worker
# -----------------------------------------------------

resource "aws_ecs_task_definition" "pentest_worker" {
  family                   = "${var.project_name}-${var.environment}-pentest-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256  # 0.25 vCPU
  memory                   = 512  # 512 MB
  execution_role_arn       = var.ecs_execution_role_arn
  task_role_arn            = var.ecs_task_role_arn

  container_definitions = jsonencode([{
    name      = "pentest-worker"
    image     = "${aws_ecr_repository.pentest_worker.repository_url}:latest"
    essential = true

    environment = [
      { name = "PENTEST_QUEUE_URL",   value = var.pentest_queue_url },
      { name = "SCANS_TABLE_NAME",    value = var.scans_table_name },
      { name = "REPORTS_BUCKET_NAME", value = var.reports_bucket_name },
      { name = "SNS_TOPIC_ARN",       value = var.sns_topic_arn }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.pentest_worker.name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "worker"
      }
    }
  }])

  tags = { Name = "${var.project_name}-${var.environment}-pentest-worker" }
}

# -----------------------------------------------------
# Task Definition — Test Target (vulnerable API)
# -----------------------------------------------------

resource "aws_ecs_task_definition" "test_target" {
  count                    = var.enable_demo_target ? 1 : 0
  family                   = "${var.project_name}-${var.environment}-test-target"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = var.ecs_execution_role_arn
  task_role_arn            = var.ecs_task_role_arn

  container_definitions = jsonencode([{
    name      = "test-target"
    image     = "${aws_ecr_repository.test_target[0].repository_url}:latest"
    essential = true

    portMappings = [{
      containerPort = 4000
      protocol      = "tcp"
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.test_target[0].name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "target"
      }
    }
  }])

  tags = { Name = "${var.project_name}-${var.environment}-test-target" }
}

# -----------------------------------------------------
# ECS Service — Pentest Worker (auto-scaling)
# -----------------------------------------------------

resource "aws_ecs_service" "pentest_worker" {
  name            = "${var.project_name}-${var.environment}-pentest-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.pentest_worker.arn
  desired_count   = 2
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.fargate.id]
    assign_public_ip = false # Private subnet, outbound via NAT
  }

  capacity_provider_strategy {
    capacity_provider = "FARGATE_SPOT"
    weight            = 1
  }

  tags = { Name = "${var.project_name}-${var.environment}-pentest-worker" }
}

# -----------------------------------------------------
# ECS Service — Test Target (always 1 instance)
# -----------------------------------------------------

resource "aws_ecs_service" "test_target" {
  count           = var.enable_demo_target ? 1 : 0
  name            = "${var.project_name}-${var.environment}-test-target"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.test_target[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.test_target[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.test_target[0].arn
  }

  tags = { Name = "${var.project_name}-${var.environment}-test-target" }
}

# -----------------------------------------------------
# Service Discovery — so pentest worker can find test-target by DNS
# -----------------------------------------------------

resource "aws_service_discovery_private_dns_namespace" "main" {
  count = var.enable_demo_target ? 1 : 0
  name = "${var.project_name}.local"
  vpc  = var.vpc_id
}

resource "aws_service_discovery_service" "test_target" {
  count = var.enable_demo_target ? 1 : 0
  name = "test-target"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main[0].id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

# -----------------------------------------------------
# Auto Scaling — Pentest Worker (scale on SQS queue depth)
# -----------------------------------------------------

resource "aws_appautoscaling_target" "pentest_worker" {
  max_capacity       = 20
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.pentest_worker.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "pentest_scale_up" {
  name               = "${var.project_name}-${var.environment}-pentest-scale-up"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.pentest_worker.resource_id
  scalable_dimension = aws_appautoscaling_target.pentest_worker.scalable_dimension
  service_namespace  = aws_appautoscaling_target.pentest_worker.service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Average"

    step_adjustment {
      scaling_adjustment          = 2
      metric_interval_lower_bound = 0
      metric_interval_upper_bound = 20
    }

    step_adjustment {
      scaling_adjustment          = 5
      metric_interval_lower_bound = 20
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "sqs_depth" {
  alarm_name          = "${var.project_name}-${var.environment}-pentest-queue-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Average"
  threshold           = 5
  alarm_actions       = [aws_appautoscaling_policy.pentest_scale_up.arn]

  dimensions = {
    QueueName = var.pentest_queue_name
  }
}

data "aws_region" "current" {}