import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError


# Add lambda directory to Python path
sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent / "lambda")
)

import handler


# ============================================================
# COMMON TEST DATA
# ============================================================

VALID_EVENT = {
    "detail": {
        "severity": "HIGH",
        "finding_type": "OPEN_SSH",
        "resource_id": "sg-test123",
        "resource_type": "AWS::EC2::SecurityGroup"
    }
}


# ============================================================
# TEST: NON-HIGH SEVERITY IS IGNORED
# ============================================================

def test_low_severity_finding_is_ignored(monkeypatch):

    publish_metric_mock = MagicMock()

    monkeypatch.setattr(
        handler,
        "publish_metric",
        publish_metric_mock
    )

    event = {
        "detail": {
            "severity": "LOW",
            "finding_type": "OPEN_SSH",
            "resource_id": "sg-test123",
            "resource_type": "AWS::EC2::SecurityGroup"
        }
    }

    result = handler.lambda_handler(
        event,
        None
    )

    assert result["statusCode"] == 200

    assert (
        result["body"]
        == "Finding ignored - severity is not HIGH"
    )

    publish_metric_mock.assert_called_with(
        "SecurityFindingsReceived"
    )


# ============================================================
# TEST: UNSUPPORTED FINDING TYPE IS IGNORED
# ============================================================

def test_unsupported_finding_type_is_ignored(monkeypatch):

    publish_metric_mock = MagicMock()

    monkeypatch.setattr(
        handler,
        "publish_metric",
        publish_metric_mock
    )

    event = {
        "detail": {
            "severity": "HIGH",
            "finding_type": "OPEN_RDP",
            "resource_id": "sg-test123",
            "resource_type": "AWS::EC2::SecurityGroup"
        }
    }

    result = handler.lambda_handler(
        event,
        None
    )

    assert result["statusCode"] == 200

    assert (
        result["body"]
        == "Finding ignored - unsupported finding type"
    )


# ============================================================
# TEST: MISSING SECURITY GROUP ID
# ============================================================

def test_missing_security_group_id(monkeypatch):

    publish_metric_mock = MagicMock()

    monkeypatch.setattr(
        handler,
        "publish_metric",
        publish_metric_mock
    )

    event = {
        "detail": {
            "severity": "HIGH",
            "finding_type": "OPEN_SSH",
            "resource_type": "AWS::EC2::SecurityGroup"
        }
    }

    result = handler.lambda_handler(
        event,
        None
    )

    assert result["statusCode"] == 400

    assert (
        result["body"]
        == "Security Group ID missing"
    )

    assert publish_metric_mock.call_count == 2


# ============================================================
# TEST: OPEN SSH RULE IS REMEDIATED
# ============================================================

def test_open_ssh_rule_is_removed(monkeypatch):

    ec2_mock = MagicMock()

    ec2_mock.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-test123",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    publish_metric_mock = MagicMock()
    notification_mock = MagicMock(
        return_value=True
    )

    monkeypatch.setattr(
        handler,
        "ec2",
        ec2_mock
    )

    monkeypatch.setattr(
        handler,
        "publish_metric",
        publish_metric_mock
    )

    monkeypatch.setattr(
        handler,
        "send_notification",
        notification_mock
    )

    result = handler.lambda_handler(
        VALID_EVENT,
        None
    )

    assert result["statusCode"] == 200

    assert (
        result["body"]
        == "Open SSH rule removed successfully"
    )

    ec2_mock.revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-test123",
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ]
            }
        ]
    )

    notification_mock.assert_called_once()


# ============================================================
# TEST: NO OPEN SSH RULE EXISTS
# ============================================================

def test_no_open_ssh_rule_found(monkeypatch):

    ec2_mock = MagicMock()

    ec2_mock.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-test123",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    publish_metric_mock = MagicMock()

    monkeypatch.setattr(
        handler,
        "ec2",
        ec2_mock
    )

    monkeypatch.setattr(
        handler,
        "publish_metric",
        publish_metric_mock
    )

    result = handler.lambda_handler(
        VALID_EVENT,
        None
    )

    assert result["statusCode"] == 200

    assert (
        result["body"]
        == (
            "No open SSH rule found. "
            "No remediation required."
        )
    )

    ec2_mock.revoke_security_group_ingress.assert_not_called()


# ============================================================
# TEST: AWS CLIENT ERROR
# ============================================================

def test_aws_client_error(monkeypatch):

    ec2_mock = MagicMock()

    ec2_mock.describe_security_groups.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "InvalidGroup.NotFound",
                    "Message": "Security group not found"
                }
            },
            "DescribeSecurityGroups"
        )
    )

    publish_metric_mock = MagicMock()

    monkeypatch.setattr(
        handler,
        "ec2",
        ec2_mock
    )

    monkeypatch.setattr(
        handler,
        "publish_metric",
        publish_metric_mock
    )

    with pytest.raises(ClientError):

        handler.lambda_handler(
            VALID_EVENT,
            None
        )

    publish_metric_mock.assert_any_call(
        "FailedRemediations"
    )
