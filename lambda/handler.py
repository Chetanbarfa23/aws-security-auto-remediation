import json
import boto3
from botocore.exceptions import ClientError


# ============================================================
# AWS CLIENTS
# ============================================================

ec2 = boto3.client("ec2")
sns = boto3.client("sns")
cloudwatch = boto3.client("cloudwatch")


# ============================================================
# CONFIGURATION
# ============================================================

SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:438546837574:security-remediation-alerts"

METRIC_NAMESPACE = "SecurityAutoRemediation"


# ============================================================
# CLOUDWATCH METRICS
# ============================================================

def publish_metric(metric_name, value=1):

    """
    Publish custom metrics to Amazon CloudWatch.
    """

    try:

        cloudwatch.put_metric_data(
            Namespace=METRIC_NAMESPACE,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": value,
                    "Unit": "Count"
                }
            ]
        )

        print(
            f"CloudWatch metric published: "
            f"{metric_name} = {value}"
        )

    except ClientError as error:

        print(
            "Failed to publish CloudWatch metric:"
        )

        print(
            error.response["Error"]["Message"]
        )


# ============================================================
# SNS NOTIFICATION
# ============================================================

def send_notification(subject, message):

    """
    Send security remediation notification through SNS.
    """

    try:

        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )

        print("=== SNS NOTIFICATION SENT ===")

        print(
            f"Message ID: "
            f"{response['MessageId']}"
        )

        # Publish notification success metric
        publish_metric(
            "NotificationsSent"
        )

        return True


    except ClientError as error:

        print(
            "=== SNS NOTIFICATION FAILED ==="
        )

        print(
            error.response["Error"]["Message"]
        )

        # Publish notification failure metric
        publish_metric(
            "NotificationFailures"
        )

        # Do not fail remediation
        # if notification fails

        return False


# ============================================================
# LAMBDA HANDLER
# ============================================================

def lambda_handler(event, context):

    print(
        "=== SECURITY FINDING RECEIVED ==="
    )

    print(
        json.dumps(
            event,
            indent=2
        )
    )


    # ========================================================
    # CLOUDWATCH METRIC
    # ========================================================

    publish_metric(
        "SecurityFindingsReceived"
    )


    # ========================================================
    # GET FINDING DETAILS
    # ========================================================

    detail = event.get(
        "detail",
        {}
    )

    # IMPORTANT:
    # These keys match your existing
    # security-finding-event.json file.

    severity = detail.get(
        "severity"
    )

    finding_type = detail.get(
        "finding_type"
    )

    security_group_id = detail.get(
        "resource"
    )


    print(
        f"Severity: {severity}"
    )

    print(
        f"Finding Type: {finding_type}"
    )

    print(
        f"Resource: {security_group_id}"
    )


    # ========================================================
    # VALIDATION
    # ========================================================

    if severity != "HIGH":

        print(
            "Finding is not HIGH severity. "
            "No remediation required."
        )

        return {
            "statusCode": 200,
            "body": (
                "Finding ignored - "
                "severity is not HIGH"
            )
        }


    if finding_type != "OpenSSH":

        print(
            "Finding type is not OpenSSH. "
            "No remediation required."
        )

        return {
            "statusCode": 200,
            "body": (
                "Finding ignored - "
                "unsupported finding type"
            )
        }


    if not security_group_id:

        print(
            "ERROR: Security Group ID missing."
        )

        publish_metric(
            "FailedRemediations"
        )

        return {
            "statusCode": 400,
            "body": (
                "Security Group ID missing"
            )
        }


    # ========================================================
    # REMEDIATION START
    # ========================================================

    print(
        "Finding validated. "
        "Starting remediation..."
    )


    # Publish remediation attempt metric

    publish_metric(
        "RemediationAttempts"
    )


    try:

        response = (
            ec2.describe_security_groups(
                GroupIds=[
                    security_group_id
                ]
            )
        )


        security_group = (
            response[
                "SecurityGroups"
            ][0]
        )


        # ====================================================
        # CHECK SECURITY GROUP RULES
        # ====================================================

        for permission in security_group.get(
            "IpPermissions",
            []
        ):


            # Check SSH Port 22

            if (

                permission.get(
                    "FromPort"
                ) == 22

                and

                permission.get(
                    "ToPort"
                ) == 22

                and

                permission.get(
                    "IpProtocol"
                ) == "tcp"

            ):


                for ip_range in permission.get(
                    "IpRanges",
                    []
                ):


                    # Check public SSH access

                    if ip_range.get(
                        "CidrIp"
                    ) == "0.0.0.0/0":


                        print(
                            f"Open SSH found in "
                            f"{security_group_id}"
                        )


                        # ====================================
                        # REMOVE INSECURE SSH RULE
                        # ====================================

                        ec2.revoke_security_group_ingress(

                            GroupId=(
                                security_group_id
                            ),

                            IpPermissions=[
                                permission
                            ]

                        )


                        print(
                            "=== REMEDIATION SUCCESSFUL ==="
                        )

                        print(
                            "Open SSH rule removed "
                            "successfully"
                        )


                        # ====================================
                        # CLOUDWATCH SUCCESS METRIC
                        # ====================================

                        publish_metric(
                            "SuccessfulRemediations"
                        )


                        # ====================================
                        # PREPARE SNS MESSAGE
                        # ====================================

                        subject = (
                            "Security Auto-Remediation Successful"
                        )


                        message = f"""
AWS SECURITY AUTO-REMEDIATION ALERT


SECURITY FINDING

Severity:
{severity}

Finding Type:
{finding_type}


AFFECTED RESOURCE

Security Group:
{security_group_id}


REMEDIATION STATUS

SUCCESSFUL


ACTION TAKEN

Public SSH access was removed.

Removed rule:

Protocol: TCP
Port: 22
Source: 0.0.0.0/0


SYSTEM COMPONENTS

- Amazon EventBridge
- AWS Lambda
- Amazon EC2
- Amazon SNS
- Amazon CloudWatch


The insecure security configuration was
automatically detected and remediated.

AWS Security Auto-Remediation System
"""


                        # ====================================
                        # SEND SNS NOTIFICATION
                        # ====================================

                        send_notification(
                            subject,
                            message
                        )


                        return {

                            "statusCode": 200,

                            "body": (
                                "Open SSH rule removed "
                                "successfully"
                            )

                        }


        # ====================================================
        # NO OPEN SSH FOUND
        # ====================================================

        print(
            "No open SSH rule found."
        )


        return {

            "statusCode": 200,

            "body": (
                "No remediation required"
            )

        }


    # ========================================================
    # AWS ERROR
    # ========================================================

    except ClientError as error:


        error_code = (
            error.response[
                "Error"
            ][
                "Code"
            ]
        )


        error_message = (
            error.response[
                "Error"
            ][
                "Message"
            ]
        )


        print(
            "=== REMEDIATION FAILED ==="
        )


        print(
            f"AWS Error Code: "
            f"{error_code}"
        )


        print(
            f"AWS Error Message: "
            f"{error_message}"
        )


        # Publish failed remediation metric

        publish_metric(
            "FailedRemediations"
        )


        raise


    # ========================================================
    # UNEXPECTED ERROR
    # ========================================================

    except Exception as error:


        print(
            "=== REMEDIATION FAILED ==="
        )


        print(
            f"Unexpected Error: "
            f"{str(error)}"
        )


        # Publish failed remediation metric

        publish_metric(
            "FailedRemediations"
        )


        raise