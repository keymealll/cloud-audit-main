"""Tests for ECS security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.ecs import (
    check_ecs_exec,
    check_privileged_task,
    check_task_logging,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_privileged_task_fail(mock_aws_provider: AWSProvider) -> None:
    """Task definition with privileged container - CRITICAL finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="priv-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "privileged": True,
                "memory": 256,
            }
        ],
    )
    result = check_privileged_task(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-001"]
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert "priv-task" in findings[0].title


def test_privileged_task_pass(mock_aws_provider: AWSProvider) -> None:
    """Task definition without privileged - no finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="safe-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "privileged": False,
                "memory": 256,
            }
        ],
    )
    result = check_privileged_task(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-001"]
    assert len(findings) == 0


def test_task_logging_fail(mock_aws_provider: AWSProvider) -> None:
    """Task definition without logging - HIGH finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="nolog-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "memory": 256,
            }
        ],
    )
    result = check_task_logging(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-002"]
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_task_logging_pass(mock_aws_provider: AWSProvider) -> None:
    """Task definition with logging - no finding."""
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.register_task_definition(
        family="logged-task",
        containerDefinitions=[
            {
                "name": "app",
                "image": "nginx:latest",
                "memory": 256,
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": "/ecs/logged-task",
                        "awslogs-region": "eu-central-1",
                        "awslogs-stream-prefix": "ecs",
                    },
                },
            }
        ],
    )
    result = check_task_logging(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-ecs-002"]
    assert len(findings) == 0


def test_ecs_exec_no_services(mock_aws_provider: AWSProvider) -> None:
    """No ECS services - no findings."""
    result = check_ecs_exec(mock_aws_provider)
    assert result.error is None
    assert len(result.findings) == 0


def test_ecs_exec_runs_without_error(mock_aws_provider: AWSProvider) -> None:
    """ECS exec check runs without error when services exist.

    Note: moto does not persist enableExecuteCommand field, so we just verify
    the check runs cleanly. The logic is tested against real AWS.
    """
    ecs = mock_aws_provider.session.client("ecs", region_name="eu-central-1")
    ecs.create_cluster(clusterName="test-cluster")
    ecs.register_task_definition(
        family="exec-task",
        containerDefinitions=[{"name": "app", "image": "nginx:latest", "memory": 256}],
    )
    ecs.create_service(
        cluster="test-cluster",
        serviceName="exec-svc",
        taskDefinition="exec-task",
        desiredCount=1,
    )
    result = check_ecs_exec(mock_aws_provider)
    assert result.error is None
    assert result.resources_scanned >= 1
