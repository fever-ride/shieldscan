# -----------------------------------------------------
# Scans Table — stores all SAST + Pentest results
# -----------------------------------------------------

resource "aws_dynamodb_table" "scans" {
  name         = "${var.project_name}-${var.environment}-scans"
  billing_mode = "PAY_PER_REQUEST" # On-demand, auto-scales, no capacity planning

  hash_key = "scan_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  attribute {
    name = "repo_name"
    type = "S"
  }

  attribute {
    name = "scan_type"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  attribute {
    name = "app_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  # GSI0: "Show all scans for an app, newest first"
  global_secondary_index {
    name            = "app-time-index"
    hash_key        = "app_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI1: "Show all scans for this repo, newest first"
  global_secondary_index {
    name            = "repo-time-index"
    hash_key        = "repo_name"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI2: "Show all critical/high findings, newest first"
  global_secondary_index {
    name            = "severity-time-index"
    hash_key        = "severity"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI3: "Show all SAST or all Pentest scans, newest first"
  global_secondary_index {
    name            = "type-time-index"
    hash_key        = "scan_type"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-scans"
  }
}

# -----------------------------------------------------
# Apps Table — unified app entity linking SAST repo + DAST target
# -----------------------------------------------------

resource "aws_dynamodb_table" "apps" {
  name         = "${var.project_name}-${var.environment}-apps"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "app_id"

  attribute {
    name = "app_id"
    type = "S"
  }

  attribute {
    name = "repo_name"
    type = "S"
  }

  attribute {
    name = "owner"
    type = "S"
  }

  attribute {
    name = "schedule"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  # GSI: look up app by repo_name (SAST webhook auto-association)
  global_secondary_index {
    name            = "repo-index"
    hash_key        = "repo_name"
    projection_type = "ALL"
  }

  # GSI: list all apps for an owner
  global_secondary_index {
    name            = "owner-index"
    hash_key        = "owner"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI: get all apps with schedule=daily/weekly for EventBridge cron
  global_secondary_index {
    name            = "schedule-time-index"
    hash_key        = "schedule"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-apps"
  }
}

# -----------------------------------------------------
# AI Feedback Table — stores AI triage + investigation results
# -----------------------------------------------------

resource "aws_dynamodb_table" "ai_feedback" {
  name         = "${var.project_name}-${var.environment}-ai-feedback"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "feedback_id"
  range_key = "created_at"

  attribute {
    name = "feedback_id"
    type = "S"
  }

  attribute {
    name = "app_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  # GSI: list all feedback for an app, newest first
  global_secondary_index {
    name            = "app-time-index"
    hash_key        = "app_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-ai-feedback"
  }
}
