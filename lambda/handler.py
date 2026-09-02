import json
import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client("ec2")


def lambda_handler(event, context):

    print("=== SECURITY FINDING RECEIVED ===")
    print(json.dumps(event, indent=2))

    # Get finding details
    detail = event.get("detail", {})

    severity = detail.get("severity")
    finding_type = detail.get("finding_type")
    security_group_id = detail.get("resource")

    print(f"Severity: {severity}")
    print(f"Finding Type: {finding_type}")
    print(f"Resource: {security_group_id}")

    # ========================================================
    # VALIDATION
    # ========================================================

    if severity != "HIGH":
        print("Finding is not HIGH severity. No remediation required.")

        return {
            "statusCode": 200,
            "body": "Finding ignored - severity is not HIGH"
        }

    if finding_type != "OpenSSH":
        print("Finding type is not OpenSSH. No remediation required.")

        return {
            "statusCode": 200,
            "body": "Finding ignored - unsupported finding type"
        }

    if not security_group_id:
        print("ERROR: Security Group ID missing.")

        return {
            "statusCode": 400,
            "body": "Security Group ID missing"
        }

    # ========================================================
    # REMEDIATION
    # ========================================================

    print("Finding validated. Starting remediation...")

    try:

        response = ec2.describe_security_groups(
            GroupIds=[security_group_id]
        )

        security_group = response["SecurityGroups"][0]

        for permission in security_group.get("IpPermissions", []):

            if (
                permission.get("FromPort") == 22
                and permission.get("ToPort") == 22
            ):

                for ip_range in permission.get("IpRanges", []):

                    if ip_range.get("CidrIp") == "0.0.0.0/0":

                        print(
                            f"Open SSH found in {security_group_id}"
                        )

                        ec2.revoke_security_group_ingress(
                            GroupId=security_group_id,
                            IpPermissions=[permission]
                        )

                        print("=== REMEDIATION SUCCESSFUL ===")
                        print("Open SSH rule removed successfully")

                        return {
                            "statusCode": 200,
                            "body": "Open SSH rule removed"
                        }

        print("No open SSH rule found.")

        return {
            "statusCode": 200,
            "body": "No remediation required"
        }

    except ClientError as error:

        error_code = error.response["Error"]["Code"]
        error_message = error.response["Error"]["Message"]

        print("=== REMEDIATION FAILED ===")
        print(f"AWS Error Code: {error_code}")
        print(f"AWS Error Message: {error_message}")

        raise

    except Exception as error:

        print("=== REMEDIATION FAILED ===")
        print(f"Unexpected Error: {str(error)}")

        raise