output "validator_function_name" {
  value = aws_lambda_function.validator.function_name
}

output "validator_invoke_arn" {
  value = aws_lambda_function.validator.invoke_arn
}

output "scanner_function_name" {
  value = aws_lambda_function.scanner.function_name
}