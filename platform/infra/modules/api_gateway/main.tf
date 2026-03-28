# -----------------------------------------------------
# HTTP API
# -----------------------------------------------------

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-${var.environment}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 3600
  }

  tags = { Name = "${var.project_name}-${var.environment}-api" }
}

# -----------------------------------------------------
# Stage (auto-deploy)
# -----------------------------------------------------

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      ip               = "$context.identity.sourceIp"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      protocol         = "$context.protocol"
      responseLength   = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/${var.project_name}-${var.environment}"
  retention_in_days = 14
}

# -----------------------------------------------------
# Cognito Authorizer (always created)
# -----------------------------------------------------

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.main.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "cognito-jwt"

  jwt_configuration {
    audience = [var.cognito_user_pool_client_id]
    issuer   = var.cognito_user_pool_endpoint
  }
}

# -----------------------------------------------------
# Route: POST /webhook/sast (NO auth — HMAC in Lambda)
# -----------------------------------------------------

resource "aws_apigatewayv2_integration" "sast_webhook" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.sast_validator_invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "sast_webhook" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /webhook/sast"
  target    = "integrations/${aws_apigatewayv2_integration.sast_webhook.id}"
}

# -----------------------------------------------------
# Route: POST /scan/pentest (Cognito auth)
# -----------------------------------------------------

resource "aws_apigatewayv2_integration" "pentest_trigger" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.pentest_trigger_invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "pentest_trigger" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /scan/pentest"
  target    = "integrations/${aws_apigatewayv2_integration.pentest_trigger.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

# -----------------------------------------------------
# Route: GET /scans (Cognito auth)
# -----------------------------------------------------

resource "aws_apigatewayv2_integration" "query" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.query_invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "query_scans" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /scans"
  target    = "integrations/${aws_apigatewayv2_integration.query.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

# -----------------------------------------------------
# Route: GET /reports/{id} (Cognito auth)
# -----------------------------------------------------

resource "aws_apigatewayv2_route" "query_report" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /reports/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.query.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

# -----------------------------------------------------
# Route: GET /targets + POST /targets (Cognito auth)
# -----------------------------------------------------

resource "aws_apigatewayv2_route" "get_targets" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "GET /targets"
  target    = "integrations/${aws_apigatewayv2_integration.query.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_route" "post_targets" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /targets"
  target    = "integrations/${aws_apigatewayv2_integration.query.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

# -----------------------------------------------------
# Lambda Permissions — allow API Gateway to invoke Lambdas
# (Centralized here to avoid circular dependencies)
# -----------------------------------------------------

resource "aws_lambda_permission" "sast_validator" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.sast_validator_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "pentest_trigger" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.pentest_trigger_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "query_api" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.query_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}