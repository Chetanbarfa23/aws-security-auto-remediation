# ============================================================
# CloudWatch Monitoring
# ============================================================

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {

  alarm_name = "security-remediation-lambda-errors"

  alarm_description = "Alerts when the security remediation Lambda fails"

  namespace = "AWS/Lambda"

  metric_name = "Errors"

  statistic = "Sum"

  period = 300

  evaluation_periods = 1

  threshold = 1

  comparison_operator = "GreaterThanOrEqualToThreshold"

  treat_missing_data = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.security_remediation.function_name
  }

  alarm_actions = [
    aws_sns_topic.security_alerts.arn
  ]

  depends_on = [
    aws_iam_role_policy.github_actions,
    aws_sns_topic.security_alerts
  ]
}


resource "aws_cloudwatch_metric_alarm" "security_dlq_messages" {

  alarm_name = "security-remediation-dlq-messages"

  alarm_description = "Alerts when failed security remediation events are present in the DLQ"

  namespace = "AWS/SQS"

  metric_name = "ApproximateNumberOfMessagesVisible"

  statistic = "Maximum"

  period = 300

  evaluation_periods = 1

  threshold = 1

  comparison_operator = "GreaterThanOrEqualToThreshold"

  treat_missing_data = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.security_dlq.name
  }

  alarm_actions = [
    aws_sns_topic.security_alerts.arn
  ]

  depends_on = [
    aws_iam_role_policy.github_actions,
    aws_sns_topic.security_alerts
  ]
}
