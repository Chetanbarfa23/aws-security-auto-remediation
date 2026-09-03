# ============================================================
# SQS Dead-Letter Queue
# ============================================================

resource "aws_sqs_queue" "security_dlq" {
  name = "security-auto-remediation-dlq"
}

# ============================================================
# Allow EventBridge to send failed events to the DLQ
# ============================================================

resource "aws_sqs_queue_policy" "security_dlq_policy" {
  queue_url = aws_sqs_queue.security_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "events.amazonaws.com"
        }

        Action = "sqs:SendMessage"

        Resource = aws_sqs_queue.security_dlq.arn

        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.security_finding.arn
          }
        }
      }
    ]
  })
}