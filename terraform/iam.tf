# ============================================================
# GitHub Actions IAM Role
# ============================================================

resource "aws_iam_role" "github_actions" {

  name = "GitHubActionsSecurityAutomationRole"

  assume_role_policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      {
        Effect = "Allow"

        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }

        Action = "sts:AssumeRoleWithWebIdentity"

        Condition = {

          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"

            "token.actions.githubusercontent.com:sub" = [
              "repo:Chetanbarfa23@182407639/aws-security-auto-remediation@1336951937:ref:refs/heads/main",
              "repo:Chetanbarfa23@182407639/aws-security-auto-remediation@1336951937:environment:production"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Project     = "AWS-Security-Auto-Remediation"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}


# ============================================================
# GitHub Actions Permissions
# ============================================================

resource "aws_iam_role_policy" "github_actions" {

  name = "GitHubActionsSecurityAutomationPolicy"

  role = aws_iam_role.github_actions.id

  policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      # ========================================================
      # Lambda Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "lambda:GetFunction",
          "lambda:ListVersionsByFunction",
          "lambda:GetFunctionCodeSigningConfig",

          # Lambda asynchronous invocation configuration
          "lambda:GetFunctionEventInvokeConfig",
          "lambda:PutFunctionEventInvokeConfig",
          "lambda:DeleteFunctionEventInvokeConfig",

          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:DeleteFunction",
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:GetPolicy"
        ]

        Resource = "*"
      },


      # ========================================================
      # EventBridge Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "events:CreateEventBus",
          "events:DeleteEventBus",
          "events:DescribeEventBus",
          "events:ListTagsForResource",
          "events:PutRule",
          "events:DeleteRule",
          "events:DescribeRule",
          "events:PutTargets",
          "events:RemoveTargets",
          "events:ListTargetsByRule"
        ]

        Resource = "*"
      },


      # ========================================================
      # Security Group Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DeleteSecurityGroup"
        ]

        Resource = "*"
      },


      # ========================================================
      # IAM Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "iam:GetRole",
          "iam:CreateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:DeleteRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:PassRole"
        ]

        Resource = [
          aws_iam_role.github_actions.arn,
          aws_iam_role.lambda_execution.arn
        ]
      },


      # ========================================================
      # OIDC Provider Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "iam:GetOpenIDConnectProvider",
          "iam:CreateOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider"
        ]

        Resource = "*"
      },


      # ========================================================
      # SQS Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "sqs:CreateQueue",
          "sqs:DeleteQueue",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:SetQueueAttributes",
          "sqs:ListQueueTags",
          "sqs:TagQueue",
          "sqs:UntagQueue"
        ]

        Resource = "*"
      },


      # ========================================================
      # CloudWatch Alarm Permissions
      # ========================================================
      #
      # Terraform needs these permissions to create, update,
      # describe, tag and delete CloudWatch alarms.
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:ListTagsForResource"
        ]

        Resource = "*"
      },


      # ========================================================
      # SNS Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "sns:CreateTopic",
          "sns:DeleteTopic",
          "sns:GetTopicAttributes",
          "sns:SetTopicAttributes",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sns:GetSubscriptionAttributes",
          "sns:ListSubscriptionsByTopic",
          "sns:TagResource",
          "sns:UntagResource",
          "sns:ListTagsForResource"
        ]

        Resource = "*"
      },


      # ========================================================
      # Terraform S3 Remote State Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "s3:ListBucket"
        ]

        Resource = "arn:aws:s3:::aws-security-auto-remediation-terraform-state-438546837574"
      },


      # ========================================================
      # Terraform State File Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]

        Resource = "arn:aws:s3:::aws-security-auto-remediation-terraform-state-438546837574/security-auto-remediation/terraform.tfstate"
      },


      # ========================================================
      # Terraform S3 Lock File Permissions
      # ========================================================

      {
        Effect = "Allow"

        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]

        Resource = "arn:aws:s3:::aws-security-auto-remediation-terraform-state-438546837574/security-auto-remediation/terraform.tfstate.tflock"
      }

    ]
  })
}