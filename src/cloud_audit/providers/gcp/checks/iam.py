"""GCP IAM checks."""

import datetime
from typing import TYPE_CHECKING
from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.gcp.provider import GCPProvider


def gcp_iam_001(provider: "GCPProvider") -> CheckResult:
    """Check for default compute engine service accounts."""
    client = provider.get_client("iam", "v1")
    project_id = provider.project_id

    result = CheckResult(
        check_id="gcp-iam-001",
        check_name="Default Compute Engine Service Account",
    )

    try:
        # Default compute engine service account format is <project-number>-compute@developer.gserviceaccount.com
        # It's better to list service accounts and check their emails
        request = client.projects().serviceAccounts().list(name=f"projects/{project_id}")
        while request is not None:
            response = request.execute()
            service_accounts = response.get("accounts", [])
            for sa in service_accounts:
                result.resources_scanned += 1
                email = sa.get("email", "")
                name = sa.get("name", "")

                if email.endswith("-compute@developer.gserviceaccount.com"):
                    cli = f"gcloud iam service-accounts disable {email}"
                    tf = f'resource "google_service_account" "default" {{\n  account_id = "..."\n  # Avoid using default SA\n}}'
                    docs = "https://cloud.google.com/iam/docs/service-accounts#default"

                    result.findings.append(
                        Finding(
                            check_id="gcp-iam-001",
                            title="Default Compute Engine Service Account is active",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="google_service_account",
                            resource_id=name,
                            region="global",
                            description="The default compute service account often has the overly permissive Editor role.",
                            recommendation="Disable the default service account and create custom ones with lowest privileges.",
                            remediation=Remediation(
                                cli=cli,
                                terraform=tf,
                                doc_url=docs,
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=["CIS GCP 1.6"],
                        )
                    )

            request = client.projects().serviceAccounts().list_next(previous_request=request, previous_response=response)
    except Exception as e:
        result.error = f"Failed to check IAM service accounts: {str(e)}"
    return result


def gcp_iam_002(provider: "GCPProvider") -> CheckResult:
    """Check for old user-managed service account keys."""
    client = provider.get_client("iam", "v1")
    project_id = provider.project_id

    result = CheckResult(
        check_id="gcp-iam-002",
        check_name="Service Account Key Rotation",
    )

    try:
        request = client.projects().serviceAccounts().list(name=f"projects/{project_id}")
        while request is not None:
            response = request.execute()
            service_accounts = response.get("accounts", [])
            for sa in service_accounts:
                email = sa.get("email", "")
                sa_name = sa.get("name", "")

                # Now get keys for this SA
                keys_request = client.projects().serviceAccounts().keys().list(
                    name=sa_name,
                    keyTypes=["USER_MANAGED"]
                )
                keys_response = keys_request.execute()
                keys = keys_response.get("keys", [])
                
                for key in keys:
                    result.resources_scanned += 1
                    key_name = key.get("name", "")
                    valid_after = key.get("validAfterTime", "")
                    
                    if valid_after:
                        # parse 2024-03-12T10:00:00Z
                        valid_after_dt = datetime.datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                        now = datetime.datetime.now(datetime.timezone.utc)
                        age_days = (now - valid_after_dt).days

                        if age_days > 90:
                            cli = f"gcloud iam service-accounts keys delete {key_name.split('/')[-1]} --iam-account={email}"
                            tf = f'resource "google_service_account_key" "mykey" {{ ... }}\n# Rotate keys periodically'
                            docs = "https://cloud.google.com/iam/docs/creating-managing-service-account-keys"

                            result.findings.append(
                                Finding(
                                    check_id="gcp-iam-002",
                                    title=f"User-managed service account key {age_days} days old (limit: 90)",
                                    severity=Severity.MEDIUM,
                                    category=Category.SECURITY,
                                    resource_type="google_service_account_key",
                                    resource_id=key_name,
                                    region="global",
                                    description="Active service account keys older than 90 days increase the window of exposure if compromised.",
                                    recommendation="Rotate and delete the old key.",
                                    remediation=Remediation(
                                        cli=cli,
                                        terraform=tf,
                                        doc_url=docs,
                                        effort=Effort.LOW,
                                    ),
                                    compliance_refs=["CIS GCP 1.4"],
                                )
                            )

            request = client.projects().serviceAccounts().list_next(previous_request=request, previous_response=response)
    except Exception as e:
        result.error = f"Failed to check IAM service account keys: {str(e)}"
    return result
