output "api_endpoint" {
  description = "API Gateway invoke URL"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "api_id" {
  value = aws_apigatewayv2_api.main.id
}

output "execution_arn" {
  value = aws_apigatewayv2_api.main.execution_arn
}