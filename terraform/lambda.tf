# ============================================================
# Lambda Execution Role
# ============================================================

resource "aws_iam_role" "lambda_execution" {

  name = "SecurityAutoRemediationLambdaRole"

  assume_role_policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      {
        Effect = "Allow"

        Principal = {
          Service = "lambda.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }

    ]

  })

}


# ============================================================
# Lambda Permissions
# ============================================================

resource "aws_iam_role_policy" "lambda_permissions" {

  name = "SecurityAutoRemediationLambdaPermissions"

  role = aws_iam_role.lambda_execution.id


  policy = jsonencode({

    Version = "2012-10-17"

    Statement = [


      # ======================================================
      # CloudWatch Logs Permissions
      # ======================================================

      {
        Effect = "Allow"

        Action = [

          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"

        ]

        Resource = "*"
      },


      # ======================================================
      # CloudWatch Custom Metrics Permissions
      # ======================================================
      #
      # Required for:
      #
      # SecurityFindingsReceived
      # RemediationAttempts
      # SuccessfulRemediations
      # FailedRemediations
      # NotificationsSent
      # NotificationFailures
      #
      # ======================================================

      {
        Effect = "Allow"

        Action = [

          "cloudwatch:PutMetricData"

        ]

        Resource = "*"
      },


      # ======================================================
      # Security Group Read Permission
      # ======================================================

      {
        Effect = "Allow"

        Action = [

          "ec2:DescribeSecurityGroups"

        ]

        Resource = "*"
      },


      # ======================================================
      # Security Group Remediation Permission
      # ======================================================

      {
        Effect = "Allow"

        Action = [

          "ec2:RevokeSecurityGroupIngress"

        ]

        # Lambda can modify ONLY our demo Security Group.
        Resource = aws_security_group.demo_insecure.arn
      },


      # ======================================================
      # SNS Notification Permission
      # ======================================================

      {
        Effect = "Allow"

        Action = [

          "sns:Publish"

        ]

        # Lambda can publish ONLY to our security alert topic.
        Resource = aws_sns_topic.security_alerts.arn
      },


      # ======================================================
      # SQS Dead-Letter Queue Permission
      # ======================================================

      {
        Effect = "Allow"

        Action = [

          "sqs:SendMessage"

        ]

        # Lambda can send failed events only to our DLQ.
        Resource = aws_sqs_queue.security_dlq.arn
      }

    ]

  })

}


# ============================================================
# Security Auto-Remediation Lambda Function
# ============================================================

resource "aws_lambda_function" "security_remediation" {

  function_name = "SecurityAutoRemediationFunction"

  runtime = "python3.12"

  handler = "handler.lambda_handler"


  # ----------------------------------------------------------
  # Lambda Deployment Package
  # ----------------------------------------------------------

  filename = "${path.module}/lambda_function.zip"


  # ----------------------------------------------------------
  # Detect Lambda Code Changes
  # ----------------------------------------------------------

  source_code_hash = filebase64sha256(
    "${path.module}/lambda_function.zip"
  )


  # ----------------------------------------------------------
  # Lambda Execution Role
  # ----------------------------------------------------------

  role = aws_iam_role.lambda_execution.arn


  # ----------------------------------------------------------
  # Ensure IAM Policy Exists Before Lambda Deployment
  # ----------------------------------------------------------

  depends_on = [
    aws_iam_role_policy.lambda_permissions
  ]

}


# ============================================================
# Lambda Asynchronous Failure Handling
# ============================================================
#
# EventBridge
#     ↓
# Lambda
#     ↓
# Retry
#     ↓
# SQS Dead-Letter Queue
#
# ============================================================

resource "aws_lambda_function_event_invoke_config" "security_remediation" {

  function_name = aws_lambda_function.security_remediation.function_name


  # Lambda keeps failed asynchronous events for up to 1 hour.

  maximum_event_age_in_seconds = 3600


  # Retry failed Lambda invocation twice.

  maximum_retry_attempts = 2


  destination_config {

    on_failure {

      # Send failed event to SQS Dead-Letter Queue.

      destination = aws_sqs_queue.security_dlq.arn

    }

  }

}