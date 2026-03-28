output "lambda_validator_role_arn" {
  value = var.use_lab_role ? data.aws_iam_role.lab_role[0].arn : aws_iam_role.lambda_validator[0].arn
}

output "lambda_sast_role_arn" {
  value = var.use_lab_role ? data.aws_iam_role.lab_role[0].arn : aws_iam_role.lambda_sast[0].arn
}

output "lambda_pentest_role_arn" {
  value = var.use_lab_role ? data.aws_iam_role.lab_role[0].arn : aws_iam_role.lambda_pentest[0].arn
}

output "lambda_query_role_arn" {
  value = var.use_lab_role ? data.aws_iam_role.lab_role[0].arn : aws_iam_role.lambda_query[0].arn
}

output "lambda_alert_role_arn" {
  value = var.use_lab_role ? data.aws_iam_role.lab_role[0].arn : aws_iam_role.lambda_alert[0].arn
}

output "ecs_execution_role_arn" {
  value = var.use_lab_role ? data.aws_iam_role.lab_role[0].arn : aws_iam_role.ecs_execution[0].arn
}

output "ecs_task_role_arn" {
  value = var.use_lab_role ? data.aws_iam_role.lab_role[0].arn : aws_iam_role.ecs_task[0].arn
}