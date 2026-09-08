# ============================================================
# Failed Remediations CloudWatch Alarm
# ============================================================

resource "aws_cloudwatch_metric_alarm" "security_remediation_failed_remediations" {

  alarm_name = "security-remediation-failed-remediations"

  alarm_description = "Alarm when Security Auto-Remediation fails to remediate a validated finding"


  # ----------------------------------------------------------
  # Custom CloudWatch Metric
  # ----------------------------------------------------------

  namespace = "SecurityAutoRemediation"

  metric_name = "FailedRemediations"


  # ----------------------------------------------------------
  # Metric Evaluation
  # ----------------------------------------------------------

  statistic = "Sum"

  period = 300

  evaluation_periods = 1

  threshold = 0

  comparison_operator = "GreaterThanThreshold"

  treat_missing_data = "notBreaching"


  # ----------------------------------------------------------
  # SNS Notification
  # ----------------------------------------------------------

  alarm_actions = [
    aws_sns_topic.security_alerts.arn
  ]

}