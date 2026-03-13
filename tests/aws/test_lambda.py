"""Tests for Lambda security checks."""

from __future__ import annotations

import zipfile
from io import BytesIO
from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.lambda_ import (
    check_deprecated_runtime,
    check_env_secrets,
    check_public_function_url,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def _make_zip() -> bytes:
    """Create a minimal Lambda deployment package."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", "def handler(event, context): return 'ok'")
    return buf.getvalue()


def _create_role(iam_client) -> str:  # noqa: ANN001
    """Create a minimal Lambda execution role and return ARN."""
    import json

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam_client.create_role(
        RoleName="lambda-role",
        AssumeRolePolicyDocument=json.dumps(policy),
    )
    return role["Role"]["Arn"]


def test_public_function_url_fail(mock_aws_provider: AWSProvider) -> None:
    """Lambda with public function URL (AuthType=NONE) - HIGH finding."""
    iam = mock_aws_provider.session.client("iam")
    role_arn = _create_role(iam)
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    lam.create_function(
        FunctionName="public-fn",
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_zip()},
    )
    lam.create_function_url_config(FunctionName="public-fn", AuthType="NONE")
    result = check_public_function_url(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-lambda-001"]
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].remediation is not None


def test_public_function_url_pass(mock_aws_provider: AWSProvider) -> None:
    """Lambda without function URL - no finding."""
    iam = mock_aws_provider.session.client("iam")
    role_arn = _create_role(iam)
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    lam.create_function(
        FunctionName="private-fn",
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_zip()},
    )
    result = check_public_function_url(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-lambda-001"]
    assert len(findings) == 0


def test_deprecated_runtime_fail(mock_aws_provider: AWSProvider) -> None:
    """Lambda with deprecated runtime - MEDIUM finding."""
    iam = mock_aws_provider.session.client("iam")
    role_arn = _create_role(iam)
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    lam.create_function(
        FunctionName="old-fn",
        Runtime="python3.8",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_zip()},
    )
    result = check_deprecated_runtime(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-lambda-002"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "python3.8" in findings[0].title


def test_deprecated_runtime_pass(mock_aws_provider: AWSProvider) -> None:
    """Lambda with current runtime - no finding."""
    iam = mock_aws_provider.session.client("iam")
    role_arn = _create_role(iam)
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    lam.create_function(
        FunctionName="new-fn",
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_zip()},
    )
    result = check_deprecated_runtime(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-lambda-002"]
    assert len(findings) == 0


def test_env_secrets_fail(mock_aws_provider: AWSProvider) -> None:
    """Lambda with secret-like env vars - HIGH finding."""
    iam = mock_aws_provider.session.client("iam")
    role_arn = _create_role(iam)
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    lam.create_function(
        FunctionName="secret-fn",
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_zip()},
        Environment={"Variables": {"DB_PASSWORD": "super-secret", "APP_NAME": "myapp"}},
    )
    result = check_env_secrets(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-lambda-003"]
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert "DB_PASSWORD" in findings[0].title


def test_env_secrets_pass(mock_aws_provider: AWSProvider) -> None:
    """Lambda with clean env vars - no finding."""
    iam = mock_aws_provider.session.client("iam")
    role_arn = _create_role(iam)
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    lam.create_function(
        FunctionName="clean-fn",
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_zip()},
        Environment={"Variables": {"APP_NAME": "myapp", "LOG_LEVEL": "INFO"}},
    )
    result = check_env_secrets(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-lambda-003"]
    assert len(findings) == 0
