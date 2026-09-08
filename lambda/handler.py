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

SNS_TOPIC_ARN = (
    "arn:aws:sns:ap-south-1:438546837574:"
    "security-remediation-alerts"
)

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

        print(
            "=== SNS NOTIFICATION SENT ==="
        )

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

        # Notification failure should not
        # fail the remediation process.

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
            indent=2,
            default=str
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


    # ========================================================
    # EXTRACT EVENT VALUES
    #
    # Primary format used by EventBridge:
    #
    # {
    #   "resource_type": "AWS::EC2::SecurityGroup",
    #   "resource_id": "sg-xxxxxxxx",
    #   "finding_type": "OPEN_SSH",
    #   "severity": "HIGH"
    # }
    #
    # Additional formats are supported for compatibility.
    # ========================================================

    severity = (
        detail.get("severity")
        or detail.get("Severity")
    )

    finding_type = (
        detail.get("finding_type")
        or detail.get("findingType")
        or detail.get("type")
    )

    security_group_id = (
        detail.get("resource_id")
        or detail.get("resourceId")
        or detail.get("resource")
    )

    resource_type = (
        detail.get("resource_type")
        or detail.get("resourceType")
    )


    # ========================================================
    # NORMALIZE VALUES
    # ========================================================

    if severity:

        severity = str(
            severity
        ).upper()


    if finding_type:

        finding_type = str(
            finding_type
        ).upper()


    print(
        f"Severity: {severity}"
    )

    print(
        f"Finding Type: {finding_type}"
    )

    print(
        f"Resource Type: {resource_type}"
    )

    print(
        f"Security Group ID: {security_group_id}"
    )


    # ========================================================
    # VALIDATE SEVERITY
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


    # ========================================================
    # VALIDATE FINDING TYPE
    #
    # Supports:
    #
    # OPEN_SSH
    # OPENSSH
    # OPEN SSH
    # ========================================================

    supported_finding_types = [
        "OPEN_SSH",
        "OPENSSH",
        "OPEN SSH"
    ]


    if finding_type not in supported_finding_types:

        print(
            "Finding type is not supported. "
            "No remediation required."
        )

        return {

            "statusCode": 200,

            "body": (
                "Finding ignored - "
                "unsupported finding type"
            )

        }


    # ========================================================
    # VALIDATE SECURITY GROUP ID
    # ========================================================

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
        "Finding validated."
    )

    print(
        "Starting remediation..."
    )


    # ========================================================
    # PUBLISH REMEDIATION ATTEMPT METRIC
    # ========================================================

    publish_metric(
        "RemediationAttempts"
    )


    try:


        # ====================================================
        # GET SECURITY GROUP DETAILS
        # ====================================================

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


        print(
            f"Security Group Found: "
            f"{security_group_id}"
        )


        remediation_performed = False


        # ====================================================
        # CHECK SECURITY GROUP INGRESS RULES
        # ====================================================

        for permission in security_group.get(
            "IpPermissions",
            []
        ):


            # =================================================
            # CHECK SSH PORT 22
            # =================================================

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


                # =============================================
                # CHECK IP RANGES
                # =============================================

                for ip_range in permission.get(
                    "IpRanges",
                    []
                ):


                    # =========================================
                    # CHECK FOR PUBLIC SSH
                    # =========================================

                    if ip_range.get(
                        "CidrIp"
                    ) == "0.0.0.0/0":


                        print(
                            "================================"
                        )

                        print(
                            "OPEN SSH DETECTED"
                        )

                        print(
                            "================================"
                        )

                        print(
                            f"Security Group: "
                            f"{security_group_id}"
                        )

                        print(
                            "Protocol: TCP"
                        )

                        print(
                            "Port: 22"
                        )

                        print(
                            "Source: 0.0.0.0/0"
                        )


                        # =====================================
                        # REMOVE ONLY THE PUBLIC SSH RULE
                        #
                        # Important:
                        # We create a specific rule instead of
                        # revoking the complete permission.
                        # =====================================

                        ec2.revoke_security_group_ingress(

                            GroupId=(
                                security_group_id
                            ),

                            IpPermissions=[
                                {
                                    "IpProtocol": "tcp",

                                    "FromPort": 22,

                                    "ToPort": 22,

                                    "IpRanges": [
                                        {
                                            "CidrIp": (
                                                "0.0.0.0/0"
                                            )
                                        }
                                    ]
                                }
                            ]

                        )


                        remediation_performed = True


                        print(
                            "================================"
                        )

                        print(
                            "REMEDIATION SUCCESSFUL"
                        )

                        print(
                            "================================"
                        )

                        print(
                            "Public SSH access removed "
                            "successfully."
                        )


                        # =====================================
                        # CLOUDWATCH SUCCESS METRIC
                        # =====================================

                        publish_metric(
                            "SuccessfulRemediations"
                        )


                        # =====================================
                        # PREPARE SNS NOTIFICATION
                        # =====================================

                        subject = (
                            "Security Auto-Remediation Successful"
                        )


                        message = f"""
AWS SECURITY AUTO-REMEDIATION ALERT


========================================
SECURITY FINDING
========================================

Severity:
{severity}

Finding Type:
{finding_type}


========================================
AFFECTED RESOURCE
========================================

Security Group:
{security_group_id}

Resource Type:
{resource_type}


========================================
REMEDIATION STATUS
========================================

SUCCESSFUL


========================================
ACTION TAKEN
========================================

Public SSH access was removed.

Removed rule:

Protocol:
TCP

Port:
22

Source:
0.0.0.0/0


========================================
SYSTEM COMPONENTS
========================================

- Amazon EventBridge
- AWS Lambda
- Amazon EC2
- Amazon SNS
- Amazon CloudWatch


The insecure security configuration was
automatically detected and remediated.

AWS Security Auto-Remediation System
"""


                        # =====================================
                        # SEND SNS NOTIFICATION
                        # =====================================

                        send_notification(
                            subject,
                            message
                        )


                        # =====================================
                        # RETURN SUCCESS
                        # =====================================

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

        if not remediation_performed:

            print(
                "================================"
            )

            print(
                "NO OPEN SSH RULE FOUND"
            )

            print(
                "================================"
            )

            print(
                "No remediation required."
            )


        return {

            "statusCode": 200,

            "body": (
                "No open SSH rule found. "
                "No remediation required."
            )

        }


    # ========================================================
    # AWS CLIENT ERROR
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
            "================================"
        )

        print(
            "REMEDIATION FAILED"
        )

        print(
            "================================"
        )


        print(
            f"AWS Error Code: "
            f"{error_code}"
        )


        print(
            f"AWS Error Message: "
            f"{error_message}"
        )


        # ====================================================
        # PUBLISH FAILED REMEDIATION METRIC
        # ====================================================

        publish_metric(
            "FailedRemediations"
        )


        raise


    # ========================================================
    # UNEXPECTED ERROR
    # ========================================================

    except Exception as error:


        print(
            "================================"
        )

        print(
            "REMEDIATION FAILED"
        )

        print(
            "================================"
        )


        print(
            f"Unexpected Error: "
            f"{str(error)}"
        )


        # ====================================================
        # PUBLISH FAILED REMEDIATION METRIC
        # ====================================================

        publish_metric(
            "FailedRemediations"
        )


        raise