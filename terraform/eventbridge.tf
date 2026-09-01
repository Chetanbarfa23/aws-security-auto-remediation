# ============================================================
# EventBridge - Security Event Bus to transfer the events creating eventbridge bus
# ============================================================

resource "aws_cloudwatch_event_bus" "security" {
  name = "security-events-bus"
}


# ============================================================
# EventBridge - Security Finding Rule. creating cloudwatch 
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
#   when rule match send this to lembda  EventBridge → Lambda Target
# ============================================================

resource "aws_cloudwatch_event_target" "security_lambda" {
  rule = aws_cloudwatch_event_rule.security_finding.name

  event_bus_name = "security-events-bus"

  target_id = "SecurityRemediationLambda"

  arn = aws_lambda_function.security_remediation.arn
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