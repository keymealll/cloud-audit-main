"""Tests for Secrets Manager checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.secrets import (
    check_secret_rotation,
    check_unused_secret,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_secret_rotation_fail(mock_aws_provider: AWSProvider) -> None:
    """Secret without rotation - MEDIUM finding."""
    sm = mock_aws_provider.session.client("secretsmanager", region_name="eu-central-1")
    sm.create_secret(Name="db-credentials", SecretString='{"user":"admin","pass":"secret"}')
    result = check_secret_rotation(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-sm-001"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "db-credentials" in findings[0].title


def test_secret_rotation_pass_no_secrets(mock_aws_provider: AWSProvider) -> None:
    """No secrets - no findings."""
    result = check_secret_rotation(mock_aws_provider)
    assert len(result.findings) == 0


def test_unused_secret_pass(mock_aws_provider: AWSProvider) -> None:
    """Recently created secret - no finding (moto doesn't set LastAccessedDate initially)."""
    sm = mock_aws_provider.session.client("secretsmanager", region_name="eu-central-1")
    sm.create_secret(Name="fresh-secret", SecretString="value")
    result = check_unused_secret(mock_aws_provider)
    # moto doesn't set LastAccessedDate by default, so no finding expected
    findings = [f for f in result.findings if f.check_id == "aws-sm-002"]
    assert len(findings) == 0


def test_unused_secret_no_secrets(mock_aws_provider: AWSProvider) -> None:
    """No secrets - no findings."""
    result = check_unused_secret(mock_aws_provider)
    assert len(result.findings) == 0
