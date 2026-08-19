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

            "token.actions.githubusercontent.com:sub" = "repo:chetanbarfa23@182407639/aws-security-auto-remediation@1336951937:ref:refs/heads/main"
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