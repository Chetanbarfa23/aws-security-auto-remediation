# ============================================================
# SNS Topic - Security Remediation Alerts
# ============================================================

resource "aws_sns_topic" "security_alerts" {

  name = "security-remediation-alerts"

  tags = {
    Project     = "AWS-Security-Auto-Remediation"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}


# ============================================================
# SNS Email Subscription
# ============================================================

resource "aws_sns_topic_subscription" "security_email" {

  topic_arn = aws_sns_topic.security_alerts.arn

  protocol = "email"

  endpoint = "barfachetan5@gmail.com"
}
