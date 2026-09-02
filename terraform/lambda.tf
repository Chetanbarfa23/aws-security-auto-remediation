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

resource "aws_iam_role_policy" "lambda_logging" {
  name = "SecurityAutoRemediationLambdaLogging"

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
  # Lambda deployment package
  # ----------------------------------------------------------
  #
  # GitHub Actions creates:
  #
  # terraform/lambda_function.zip
  #
  # The ZIP is uploaded as a GitHub Actions artifact during
  # the Plan job and downloaded during the Apply job.
  # ----------------------------------------------------------

  filename = "${path.module}/lambda_function.zip"

  # ----------------------------------------------------------
  # Detect Lambda code changes
  # ----------------------------------------------------------

  source_code_hash = filebase64sha256(
    "${path.module}/lambda_function.zip"
  )

  role = aws_iam_role.lambda_execution.arn
}