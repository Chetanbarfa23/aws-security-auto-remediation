############################################
# CloudWatch Dashboard - Security Auto-Remediation (v2, redesigned)
# File: terraform/dashboard.tf
#
# Redesign goals (see chat for full rationale):
#  - Separate BUSINESS/SECURITY metrics (custom, namespace
#    "SecurityAutoRemediation") from TECHNICAL Lambda metrics
#    (AWS/Lambda: Invocations, Errors, Duration).
#  - Put the most important numbers first, as large single-value
#    KPI widgets, so status is readable in seconds.
#  - Use graphs only where a trend over time is genuinely useful
#    (Remediation Activity, Lambda Performance) rather than for
#    every metric.
#  - Keep the existing dashboard name so no resources are duplicated.
############################################

data "aws_caller_identity" "current" {}

locals {
  dashboard_region = "ap-south-1"

  lambda_function_name = "SecurityAutoRemediationFunction"
  dlq_queue_name        = "security-auto-remediation-dlq"

  lambda_error_alarm_name       = "security-remediation-lambda-errors"
  dlq_alarm_name                 = "security-remediation-dlq-messages"
  failed_remediation_alarm_name  = "security-remediation-failed-remediations"

  lambda_error_alarm_arn      = "arn:aws:cloudwatch:${local.dashboard_region}:${data.aws_caller_identity.current.account_id}:alarm:${local.lambda_error_alarm_name}"
  dlq_alarm_arn               = "arn:aws:cloudwatch:${local.dashboard_region}:${data.aws_caller_identity.current.account_id}:alarm:${local.dlq_alarm_name}"
  failed_remediation_alarm_arn = "arn:aws:cloudwatch:${local.dashboard_region}:${data.aws_caller_identity.current.account_id}:alarm:${local.failed_remediation_alarm_name}"

  custom_ns = "SecurityAutoRemediation"
}

resource "aws_cloudwatch_dashboard" "security_auto_remediation_dashboard" {
  # Same name as before — this UPDATES the existing dashboard in place,
  # it does not create a second one.
  dashboard_name = "security-auto-remediation-dashboard"

  dashboard_body = jsonencode({
    widgets = [

      ############################################
      # HEADER
      ############################################
      {
        type = "text", x = 0, y = 0, width = 24, height = 2,
        properties = {
          markdown = "# AWS Security Auto-Remediation Dashboard\nReal-time monitoring of security findings, automated remediation actions, system health, failures, and notifications."
        }
      },
      {
        type = "text", x = 0, y = 2, width = 24, height = 5,
        properties = {
          markdown = "**Security Workflow**\n\n🚨 Security Finding → 📥 EventBridge → ⚡ Lambda → 🔍 Security Group Analysis → 🛠️ Automatic Remediation → 📊 Metrics Updated → 📧 SNS Notification"
        }
      },

      ############################################
      # SECTION 2: SECURITY OVERVIEW (KPIs)
      # Large single-value widgets = "understand status in
      # seconds" per the requirement. All use Sum over the
      # dashboard's selected time range, since these are event
      # counts, not rates or durations.
      ############################################
      { type = "text", x = 0, y = 7, width = 24, height = 1, properties = { markdown = "## Security Overview" } },

      {
        type = "metric", x = 0, y = 8, width = 8, height = 4,
        properties = {
          title = "🚨 Security Events Received", region = local.dashboard_region, view = "singleValue", period = 3600, stat = "Sum",
          metrics = [[local.custom_ns, "SecurityFindingsReceived"]]
        }
      },
      {
        type = "metric", x = 8, y = 8, width = 8, height = 4,
        properties = {
          title = "⚡ Lambda Executions", region = local.dashboard_region, view = "singleValue", period = 3600, stat = "Sum",
          metrics = [["AWS/Lambda", "Invocations", "FunctionName", local.lambda_function_name]]
        }
      },
      {
        type = "metric", x = 16, y = 8, width = 8, height = 4,
        properties = {
          title = "✅ Successful Remediations", region = local.dashboard_region, view = "singleValue", period = 3600, stat = "Sum",
          metrics = [[local.custom_ns, "SuccessfulRemediations", { color = "#2ca02c" }]]
        }
      },
      {
        type = "metric", x = 0, y = 12, width = 8, height = 4,
        properties = {
          title = "❌ Failed Remediations", region = local.dashboard_region, view = "singleValue", period = 3600, stat = "Sum",
          metrics = [[local.custom_ns, "FailedRemediations", { color = "#d62728" }]]
        }
      },
      {
        type = "metric", x = 8, y = 12, width = 8, height = 4,
        properties = {
          title = "⚠️ DLQ Messages", region = local.dashboard_region, view = "singleValue", period = 300, stat = "Maximum",
          metrics = [["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", local.dlq_queue_name, { color = "#ff7f0e" }]]
        }
      },
      {
        type = "metric", x = 16, y = 12, width = 8, height = 4,
        properties = {
          title = "📧 Notifications Sent", region = local.dashboard_region, view = "singleValue", period = 3600, stat = "Sum",
          metrics = [[local.custom_ns, "NotificationsSent"]]
        }
      },

      ############################################
      # SECTION 3: REMEDIATION ACTIVITY
      # A single overlaid time series so "events received" vs
      # "successful" vs "failed" can be visually compared, which
      # is the #1 story the dashboard needs to tell. Sum/5-min
      # period: these are discrete event counts, so summing per
      # bucket shows real activity instead of noisy per-second dots.
      ############################################
      { type = "text", x = 0, y = 16, width = 24, height = 1, properties = { markdown = "## Remediation Activity" } },
      {
        type = "metric", x = 0, y = 17, width = 24, height = 6,
        properties = {
          title = "Security Findings vs Successful vs Failed Remediations", region = local.dashboard_region,
          view = "timeSeries", stacked = false, period = 300, stat = "Sum",
          metrics = [
            [local.custom_ns, "SecurityFindingsReceived", { label = "Findings Received", color = "#1f77b4" }],
            [local.custom_ns, "SuccessfulRemediations", { label = "Successful Remediations", color = "#2ca02c" }],
            [local.custom_ns, "FailedRemediations", { label = "Failed Remediations", color = "#d62728" }]
          ]
        }
      },

      ############################################
      # SECTION 4: LAMBDA PERFORMANCE
      # Kept strictly to raw AWS/Lambda technical metrics so this
      # section reads as "is the function itself healthy", separate
      # from "did remediation succeed" above. Sum for counts,
      # Average for duration (a spike in Maximum duration is normal
      # cold-start noise and would be confusing to a fresher).
      ############################################
      { type = "text", x = 0, y = 23, width = 24, height = 1, properties = { markdown = "## Lambda Performance (Technical Metrics)" } },
      {
        type = "metric", x = 0, y = 24, width = 8, height = 6,
        properties = {
          title = "⚡ Lambda Executions", region = local.dashboard_region, view = "timeSeries", period = 300, stat = "Sum",
          metrics = [["AWS/Lambda", "Invocations", "FunctionName", local.lambda_function_name]]
        }
      },
      {
        type = "metric", x = 8, y = 24, width = 8, height = 6,
        properties = {
          title = "🔴 Lambda Errors", region = local.dashboard_region, view = "timeSeries", period = 300, stat = "Sum",
          metrics = [["AWS/Lambda", "Errors", "FunctionName", local.lambda_function_name, { color = "#d62728" }]]
        }
      },
      {
        type = "metric", x = 16, y = 24, width = 8, height = 6,
        properties = {
          title = "⏱️ Lambda Response Time", region = local.dashboard_region, view = "timeSeries", period = 300, stat = "Average",
          metrics = [["AWS/Lambda", "Duration", "FunctionName", local.lambda_function_name, { color = "#9467bd" }]]
        }
      },

      ############################################
      # SECTION 5: SYSTEM HEALTH
      # CloudWatch dashboards cannot compute a derived "traffic
      # light" purely from a formula across three alarms in one
      # widget, so the practical approach (per your fallback
      # instruction) is: a native alarm-status widget for the
      # exact machine-checked state, plus a text widget explaining
      # the health rule in plain language beside it.
      ############################################
      { type = "text", x = 0, y = 30, width = 24, height = 1, properties = { markdown = "## System Health" } },
      {
        type = "alarm", x = 0, y = 31, width = 12, height = 6,
        properties = {
          title = "Security Monitoring Alarm Status",
          alarms = [
            local.lambda_error_alarm_arn,
            local.dlq_alarm_arn,
            local.failed_remediation_alarm_arn
          ]
        }
      },
      {
        type = "text", x = 12, y = 31, width = 12, height = 6,
        properties = {
          markdown = "**How to read this:**\n\n🟢 All alarms OK → Lambda Errors = 0, Failed Remediations = 0, DLQ Messages = 0 → system is healthy.\n\n🟡/🔴 Any alarm in ALARM state → check the corresponding widget above (Lambda Performance, Remediation Activity, or DLQ below) to see which part needs attention."
        }
      },

      ############################################
      # SECTION 6: FAILED EVENTS AND DLQ
      ############################################
      { type = "text", x = 0, y = 37, width = 24, height = 1, properties = { markdown = "## Failed Events and DLQ" } },
      {
        type = "metric", x = 0, y = 38, width = 12, height = 6,
        properties = {
          title = "⚠️ DLQ Message Count", region = local.dashboard_region, view = "timeSeries", period = 300, stat = "Maximum",
          metrics = [["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", local.dlq_queue_name, { color = "#ff7f0e" }]]
        }
      },
      {
        type = "text", x = 12, y = 38, width = 12, height = 6,
        properties = {
          markdown = "**What this means:**\n\n**0** = No failed events waiting — every EventBridge delivery to Lambda succeeded (or was retried successfully).\n\n**Greater than 0** = One or more events exhausted their 3 retry attempts and landed in the Dead Letter Queue. These need manual investigation."
        }
      },

      ############################################
      # SECTION 7: NOTIFICATION STATUS
      ############################################
      { type = "text", x = 0, y = 44, width = 24, height = 1, properties = { markdown = "## Notification Status" } },
      {
        type = "metric", x = 0, y = 45, width = 24, height = 6,
        properties = {
          title = "📧 Notifications Sent Over Time", region = local.dashboard_region, view = "timeSeries", period = 300, stat = "Sum",
          metrics = [[local.custom_ns, "NotificationsSent"]]
        }
      }
    ]
  })
}

output "dashboard_name" {
  value = aws_cloudwatch_dashboard.security_auto_remediation_dashboard.dashboard_name
}

output "dashboard_console_url" {
  value = "https://${local.dashboard_region}.console.aws.amazon.com/cloudwatch/home?region=${local.dashboard_region}#dashboards:name=${aws_cloudwatch_dashboard.security_auto_remediation_dashboard.dashboard_name}"
}
