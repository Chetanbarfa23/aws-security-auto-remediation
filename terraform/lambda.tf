# ============================================================
# Lambda Execution Role
# ============================================================

# An IAM role is a temporary AWS identity with permissions.
resource "aws_iam_role" "lambda_execution" {
  name = "SecurityAutoRemediationLambdaRole"

  # Trust policy:
  # "Who is allowed to assume/use this role?"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    # Inside Statement there are rules that need to be followed.
    Statement = [
      {
        Effect = "Allow"

        # "I allow Lambda to assume this IAM role."
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

# This policy answers:
# "What is Lambda allowed to do after it assumes the role?"
resource "aws_iam_role_policy" "lambda_logging" {
  name = "SecurityAutoRemediationLambdaLogging"

  # Attach this policy to our Lambda execution role.
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # ======================================================
      # CloudWatch Logs Permissions
      # ======================================================

      {
        Effect = "Allow"

        # Lambda needs these permissions to write logs.
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]

        # CloudWatch Logs permissions use "*".
        Resource = "*"
      },


      # ======================================================
      # Security Group Read Permission
      # ======================================================

      {
        Effect = "Allow"

        # Lambda needs to read Security Group rules
        # before deciding whether remediation is required.
        Action = [
          "ec2:DescribeSecurityGroups"
        ]

        # DescribeSecurityGroups requires "*".
        Resource = "*"
      },


      # ======================================================
      # Security Group Remediation Permission
      # ======================================================

      {
        Effect = "Allow"

        # Lambda can remove an unwanted ingress rule.
        Action = [
          "ec2:RevokeSecurityGroupIngress"
        ]

        # IMPORTANT:
        # Lambda can modify ONLY our demo Security Group.
        Resource = aws_security_group.demo_insecure.arn
      }
    ]
  })
}


# ============================================================
# Package Lambda Python Code
# ============================================================

data "archive_file" "lambda_package" {
  type = "zip"

  source_file = "${path.module}/../lambda/handler.py"

  output_path = "${path.module}/lambda_function.zip"
}


# ============================================================
# Security Auto-Remediation Lambda Function
# ============================================================

resource "aws_lambda_function" "security_remediation" {
  function_name = "SecurityAutoRemediationFunction"

  runtime = "python3.12"

  handler = "handler.lambda_handler"

  filename = data.archive_file.lambda_package.output_path

  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  role = aws_iam_role.lambda_execution.arn
}