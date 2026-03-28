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
    name = "created_at"
    type = "S"
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
# Scan Targets Table — registered pentest API URLs
# -----------------------------------------------------

resource "aws_dynamodb_table" "scan_targets" {
  name         = "${var.project_name}-${var.environment}-scan-targets"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "target_id"

  attribute {
    name = "target_id"
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

  # GSI: "Get all targets with schedule=daily for EventBridge cron"
  global_secondary_index {
    name            = "schedule-time-index"
    hash_key        = "schedule"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-scan-targets"
  }
}
