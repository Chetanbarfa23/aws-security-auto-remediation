# ============================================================
# EventBridge - Security Event Bus
# ============================================================

resource "aws_cloudwatch_event_bus" "security" {
  name = "security-events-bus"
}


# ============================================================
# EventBridge - Security Finding Rule
# ============================================================

resource "aws_cloudwatch_event_rule" "security_finding" {
  name           = "security-finding-rule"
  description    = "Matches simulated security findings for auto-remediation"
  event_bus_name = aws_cloudwatch_event_bus.security.name

  event_pattern = jsonencode({
    source = [
      "security.simulator"
    ]

    detail-type = [
      "Security Finding"
    ]
  })
}


# ============================================================
# EventBridge → Lambda Target
# ============================================================

resource "aws_cloudwatch_event_target" "security_lambda" {
  rule = aws_cloudwatch_event_rule.security_finding.name

  event_bus_name = aws_cloudwatch_event_bus.security.name

  target_id = "SecurityRemediationLambda"

  arn = aws_lambda_function.security_remediation.arn


  # ----------------------------------------------------------
  # Retry Configuration
  # ----------------------------------------------------------

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 3
  }


  # ----------------------------------------------------------
  # Dead-Letter Queue
  # ----------------------------------------------------------

  dead_letter_config {
    arn = aws_sqs_queue.security_dlq.arn
  }
}


# ============================================================
# Allow EventBridge to Invoke Lambda
# ============================================================

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id = "AllowEventBridgeInvoke"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.security_remediation.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.security_finding.arn
}