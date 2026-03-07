"""Tests for SSM security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.ssm import (
    check_ec2_not_managed,
    check_insecure_parameters,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_ec2_not_managed_no_instances(mock_aws_provider: AWSProvider) -> None:
    """No running instances - no findings."""
    result = check_ec2_not_managed(mock_aws_provider)
    assert len(result.findings) == 0


def test_ec2_not_managed_handles_error(mock_aws_provider: AWSProvider) -> None:
    """Check handles SSM API errors gracefully.

    Note: moto does not implement describe_instance_information, so the check
    will catch the error. We verify it doesn't crash. Logic tested on real AWS.
    """
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    result = check_ec2_not_managed(mock_aws_provider)
    # The check catches the NotImplementedError from moto and sets error
    assert result.error is not None or result.resources_scanned == 0


def test_insecure_parameters_fail(mock_aws_provider: AWSProvider) -> None:
    """SSM parameter with secret name but type String - HIGH finding."""
    ssm = mock_aws_provider.session.client("ssm", region_name="eu-central-1")
    ssm.put_parameter(Name="/app/db_password", Value="secret123", Type="String")
    result = check_insecure_parameters(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ssm-002"]
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert "db_password" in findings[0].title


def test_insecure_parameters_pass(mock_aws_provider: AWSProvider) -> None:
    """SSM parameter with secret name and type SecureString - no finding."""
    ssm = mock_aws_provider.session.client("ssm", region_name="eu-central-1")
    ssm.put_parameter(Name="/app/api_key", Value="secret123", Type="SecureString")
    result = check_insecure_parameters(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ssm-002"]
    assert len(findings) == 0
