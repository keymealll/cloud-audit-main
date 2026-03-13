"""ECS security checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_privileged_task(provider: AWSProvider) -> CheckResult:
    """Check for ECS task definitions with privileged containers."""
    result = CheckResult(check_id="aws-ecs-001", check_name="ECS privileged containers")

    try:
        for region in provider.regions:
            ecs = provider.session.client("ecs", region_name=region)
            paginator = ecs.get_paginator("list_task_definitions")
            for page in paginator.paginate(status="ACTIVE"):
                for td_arn in page["taskDefinitionArns"]:
                    result.resources_scanned += 1
                    try:
                        td = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
                        family = td.get("family", td_arn)
                        for container in td.get("containerDefinitions", []):
                            if container.get("privileged", False):
                                container_name = container.get("name", "unknown")
                                result.findings.append(
                                    Finding(
                                        check_id="aws-ecs-001",
                                        title=f"ECS task '{family}' has privileged container '{container_name}'",
                                        severity=Severity.CRITICAL,
                                        category=Category.SECURITY,
                                        resource_type="AWS::ECS::TaskDefinition",
                                        resource_id=td_arn,
                                        region=region,
                                        description=f"Container '{container_name}' in task definition '{family}' runs with privileged mode. This gives the container root-level access to the host.",
                                        recommendation="Remove privileged mode. Use specific Linux capabilities instead if needed.",
                                        remediation=Remediation(
                                            cli=(
                                                f"# Register a new task definition revision without privileged mode:\n"
                                                f"# 1. Describe current: aws ecs describe-task-definition --task-definition {family}\n"
                                                f'# 2. Remove "privileged": true from containerDefinitions\n'
                                                f"# 3. Register: aws ecs register-task-definition --cli-input-json file://updated-td.json"
                                            ),
                                            terraform=(
                                                f'resource "aws_ecs_task_definition" "{family}" {{\n'
                                                f"  container_definitions = jsonencode([{{\n"
                                                f'    name       = "{container_name}"\n'
                                                f"    privileged = false  # Never run privileged\n"
                                                f"    # ...\n"
                                                f"  }}])\n"
                                                f"}}"
                                            ),
                                            doc_url="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definition_security",
                                            effort=Effort.MEDIUM,
                                        ),
                                    )
                                )
                                break  # One finding per task definition
                    except Exception:
                        continue
    except Exception as e:
        result.error = str(e)

    return result


def check_task_logging(provider: AWSProvider) -> CheckResult:
    """Check for ECS task definitions without log configuration."""
    result = CheckResult(check_id="aws-ecs-002", check_name="ECS task logging")

    try:
        for region in provider.regions:
            ecs = provider.session.client("ecs", region_name=region)
            paginator = ecs.get_paginator("list_task_definitions")
            for page in paginator.paginate(status="ACTIVE"):
                for td_arn in page["taskDefinitionArns"]:
                    result.resources_scanned += 1
                    try:
                        td = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
                        family = td.get("family", td_arn)
                        for container in td.get("containerDefinitions", []):
                            container_name = container.get("name", "unknown")
                            if not container.get("logConfiguration"):
                                result.findings.append(
                                    Finding(
                                        check_id="aws-ecs-002",
                                        title=f"ECS container '{container_name}' in task '{family}' has no log configuration",
                                        severity=Severity.HIGH,
                                        category=Category.SECURITY,
                                        resource_type="AWS::ECS::TaskDefinition",
                                        resource_id=td_arn,
                                        region=region,
                                        description=f"Container '{container_name}' in task definition '{family}' has no logConfiguration. Container output is lost, making debugging and security investigation impossible.",
                                        recommendation="Add a logConfiguration using awslogs, splunk, or another supported log driver.",
                                        remediation=Remediation(
                                            cli=(
                                                f"# Add logging to the container definition:\n"
                                                f"# In the containerDefinitions JSON, add:\n"
                                                f'# "logConfiguration": {{\n'
                                                f'#   "logDriver": "awslogs",\n'
                                                f'#   "options": {{\n'
                                                f'#     "awslogs-group": "/ecs/{family}",\n'
                                                f'#     "awslogs-region": "{region}",\n'
                                                f'#     "awslogs-stream-prefix": "ecs"\n'
                                                f"#   }}\n"
                                                f"# }}"
                                            ),
                                            terraform=(
                                                f'resource "aws_ecs_task_definition" "{family}" {{\n'
                                                f"  container_definitions = jsonencode([{{\n"
                                                f'    name = "{container_name}"\n'
                                                f"    logConfiguration = {{\n"
                                                f'      logDriver = "awslogs"\n'
                                                f"      options = {{\n"
                                                f'        "awslogs-group"         = "/ecs/{family}"\n'
                                                f'        "awslogs-region"        = "{region}"\n'
                                                f'        "awslogs-stream-prefix" = "ecs"\n'
                                                f"      }}\n"
                                                f"    }}\n"
                                                f"  }}])\n"
                                                f"}}"
                                            ),
                                            doc_url="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html",
                                            effort=Effort.LOW,
                                        ),
                                    )
                                )
                    except Exception:
                        continue
    except Exception as e:
        result.error = str(e)

    return result


def check_ecs_exec(provider: AWSProvider) -> CheckResult:
    """Check for ECS services with execute command enabled."""
    result = CheckResult(check_id="aws-ecs-003", check_name="ECS Exec enabled")

    try:
        for region in provider.regions:
            ecs = provider.session.client("ecs", region_name=region)
            clusters_resp = ecs.list_clusters()
            for cluster_arn in clusters_resp.get("clusterArns", []):
                try:
                    svc_paginator = ecs.get_paginator("list_services")
                    for svc_page in svc_paginator.paginate(cluster=cluster_arn):
                        svc_arns = svc_page.get("serviceArns", [])
                        if not svc_arns:
                            continue
                        services = ecs.describe_services(cluster=cluster_arn, services=svc_arns)["services"]
                        for svc in services:
                            result.resources_scanned += 1
                            svc_name = svc.get("serviceName", "unknown")
                            if svc.get("enableExecuteCommand", False):
                                result.findings.append(
                                    Finding(
                                        check_id="aws-ecs-003",
                                        title=f"ECS service '{svc_name}' has ECS Exec enabled",
                                        severity=Severity.MEDIUM,
                                        category=Category.SECURITY,
                                        resource_type="AWS::ECS::Service",
                                        resource_id=svc.get("serviceArn", svc_name),
                                        region=region,
                                        description=f"Service '{svc_name}' has enableExecuteCommand=true. This allows interactive shell access to running containers, which can be a security risk in production.",
                                        recommendation="Disable ECS Exec in production environments. Use it only for debugging in non-production.",
                                        remediation=Remediation(
                                            cli=(
                                                f"aws ecs update-service --cluster {cluster_arn} "
                                                f"--service {svc_name} "
                                                f"--no-enable-execute-command --region {region}"
                                            ),
                                            terraform=(
                                                f'resource "aws_ecs_service" "{svc_name}" {{\n'
                                                f"  # ...\n"
                                                f"  enable_execute_command = false  # Disable in production\n"
                                                f"}}"
                                            ),
                                            doc_url="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html",
                                            effort=Effort.LOW,
                                        ),
                                    )
                                )
                except Exception:
                    continue
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all ECS checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_privileged_task, provider),
        partial(check_task_logging, provider),
        partial(check_ecs_exec, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    return checks
