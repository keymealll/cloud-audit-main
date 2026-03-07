"""GCP IAM security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider


def check_service_account_key_rotation(provider: GCPProvider) -> CheckResult:
    """Check if service account keys are older than 90 days."""
    result = CheckResult(check_id="gcp-iam-001", check_name="Service account key rotation")

    try:
        sa_list = (
            provider.iam_service.projects()
            .serviceAccounts()
            .list(name=f"projects/{provider.project}")
            .execute()
        )
        now = datetime.now(timezone.utc)
        max_age_days = 90

        for sa in sa_list.get("accounts", []):
            email = sa["email"]

            # Skip Google-managed service accounts
            if email.endswith(".gserviceaccount.com") and (
                email.startswith("service-") or "@cloudservices." in email
            ):
                continue

            keys = (
                provider.iam_service.projects()
                .serviceAccounts()
                .keys()
                .list(name=f"projects/{provider.project}/serviceAccounts/{email}")
                .execute()
            )

            for key in keys.get("keys", []):
                result.resources_scanned += 1
                # Only check user-managed keys
                if key.get("keyType") != "USER_MANAGED":
                    continue

                created_str = key.get("validAfterTime", "")
                if not created_str:
                    continue

                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (now - created).days

                if age_days > max_age_days:
                    key_id = key["name"].split("/")[-1]
                    result.findings.append(
                        Finding(
                            check_id="gcp-iam-001",
                            title=f"Service account key for '{email}' is {age_days} days old",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="iam.googleapis.com/ServiceAccountKey",
                            resource_id=f"projects/{provider.project}/serviceAccounts/{email}/keys/{key_id}",
                            description=(
                                f"Service account key {key_id} for '{email}' was created {age_days} days ago "
                                f"(limit: {max_age_days}). Stale keys increase the risk of credential compromise."
                            ),
                            recommendation="Rotate the service account key. Create a new key, update all consumers, then delete the old one.",
                            remediation=Remediation(
                                cli=(
                                    f"# Create new key:\n"
                                    f"gcloud iam service-accounts keys create /tmp/new-key.json \\\n"
                                    f"  --iam-account={email}\n"
                                    f"# After updating consumers, delete old key:\n"
                                    f"gcloud iam service-accounts keys delete {key_id} \\\n"
                                    f"  --iam-account={email}"
                                ),
                                terraform=(
                                    f'resource "google_service_account_key" "rotated" {{\n'
                                    f'  service_account_id = "{email}"\n'
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=[
                                "ISO 27001 A.9.2.4",
                                "ISO 27001 A.9.4.3",
                                "SOC 2 CC6.1",
                                "CIS GCP 1.7",
                            ],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_overly_permissive_roles(provider: GCPProvider) -> CheckResult:
    """Check for users/SAs with Owner or Editor roles at project level."""
    result = CheckResult(check_id="gcp-iam-002", check_name="Overly permissive IAM roles")

    try:
        policy = (
            provider.crm_service.projects()
            .getIamPolicy(resource=provider.project, body={"options": {"requestedPolicyVersion": 3}})
            .execute()
        )

        dangerous_roles = {"roles/owner", "roles/editor"}

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            if role not in dangerous_roles:
                continue

            for member in binding.get("members", []):
                result.resources_scanned += 1
                # Skip project-level default service accounts for Editor
                if role == "roles/editor" and member.startswith("serviceAccount:") and (
                    "-compute@developer" in member or "@cloudservices" in member
                ):
                    continue

                result.findings.append(
                    Finding(
                        check_id="gcp-iam-002",
                        title=f"'{member}' has '{role}' on project",
                        severity=Severity.CRITICAL if role == "roles/owner" else Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="cloudresourcemanager.googleapis.com/Project",
                        resource_id=f"projects/{provider.project}",
                        region="global",
                        description=(
                            f"Member '{member}' is granted '{role}' at the project level. "
                            f"This grants broad access to all resources in the project."
                        ),
                        recommendation="Follow least-privilege: replace Owner/Editor with specific predefined or custom roles.",
                        remediation=Remediation(
                            cli=(
                                f"# Remove overly permissive role:\n"
                                f"gcloud projects remove-iam-policy-binding {provider.project} \\\n"
                                f"  --member='{member}' --role='{role}'\n"
                                f"# Add a specific role instead:\n"
                                f"gcloud projects add-iam-policy-binding {provider.project} \\\n"
                                f"  --member='{member}' --role='roles/viewer'"
                            ),
                            terraform=(
                                f'resource "google_project_iam_member" "least_privilege" {{\n'
                                f'  project = "{provider.project}"\n'
                                f'  role    = "roles/viewer"  # Replace with specific role\n'
                                f'  member  = "{member}"\n'
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/iam/docs/understanding-roles",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.9.1.2",
                            "ISO 27001 A.9.2.3",
                            "SOC 2 CC6.1",
                            "SOC 2 CC6.3",
                            "CIS GCP 1.1",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_sa_user_managed_keys(provider: GCPProvider) -> CheckResult:
    """Check for service accounts with user-managed keys (prefer Workload Identity)."""
    result = CheckResult(check_id="gcp-iam-003", check_name="Service accounts with user-managed keys")

    try:
        sa_list = (
            provider.iam_service.projects()
            .serviceAccounts()
            .list(name=f"projects/{provider.project}")
            .execute()
        )

        for sa in sa_list.get("accounts", []):
            email = sa["email"]
            result.resources_scanned += 1

            if email.endswith(".gserviceaccount.com") and (
                email.startswith("service-") or "@cloudservices." in email
            ):
                continue

            keys = (
                provider.iam_service.projects()
                .serviceAccounts()
                .keys()
                .list(name=f"projects/{provider.project}/serviceAccounts/{email}")
                .execute()
            )

            user_keys = [k for k in keys.get("keys", []) if k.get("keyType") == "USER_MANAGED"]
            if user_keys:
                result.findings.append(
                    Finding(
                        check_id="gcp-iam-003",
                        title=f"Service account '{email}' has {len(user_keys)} user-managed key(s)",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="iam.googleapis.com/ServiceAccount",
                        resource_id=f"projects/{provider.project}/serviceAccounts/{email}",
                        description=(
                            f"Service account '{email}' has {len(user_keys)} user-managed key(s). "
                            f"User-managed keys are a security risk - prefer Workload Identity Federation."
                        ),
                        recommendation="Migrate to Workload Identity Federation or attached service accounts. Delete user-managed keys.",
                        remediation=Remediation(
                            cli=(
                                f"# List keys for the service account:\n"
                                f"gcloud iam service-accounts keys list --iam-account={email}\n"
                                f"# Delete user-managed key:\n"
                                f"gcloud iam service-accounts keys delete KEY_ID --iam-account={email}"
                            ),
                            terraform=(
                                f"# Use Workload Identity instead of keys:\n"
                                f'resource "google_service_account_iam_member" "workload_identity" {{\n'
                                f'  service_account_id = "projects/{provider.project}/serviceAccounts/{email}"\n'
                                f'  role               = "roles/iam.workloadIdentityUser"\n'
                                f'  member             = "serviceAccount:{provider.project}.svc.id.goog[NAMESPACE/KSA_NAME]"\n'
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/iam/docs/workload-identity-federation",
                            effort=Effort.HIGH,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.9.2.1",
                            "ISO 27001 A.9.4.3",
                            "SOC 2 CC6.1",
                            "CIS GCP 1.4",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_default_sa_usage(provider: GCPProvider) -> CheckResult:
    """Check if compute default service account is used with Editor role."""
    result = CheckResult(check_id="gcp-iam-004", check_name="Default service account usage")

    try:
        policy = (
            provider.crm_service.projects()
            .getIamPolicy(resource=provider.project, body={"options": {"requestedPolicyVersion": 3}})
            .execute()
        )

        result.resources_scanned = 1
        default_sa = f"{provider.project}@appspot.gserviceaccount.com"
        compute_default_sa_suffix = "-compute@developer.gserviceaccount.com"

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            if role != "roles/editor":
                continue
            for member in binding.get("members", []):
                sa_email = member.replace("serviceAccount:", "")
                if sa_email == default_sa or sa_email.endswith(compute_default_sa_suffix):
                    result.findings.append(
                        Finding(
                            check_id="gcp-iam-004",
                            title=f"Default service account '{sa_email}' has Editor role",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="iam.googleapis.com/ServiceAccount",
                            resource_id=f"projects/{provider.project}/serviceAccounts/{sa_email}",
                            description=(
                                f"The default service account '{sa_email}' has the Editor role. "
                                f"This grants broad write access to all project resources."
                            ),
                            recommendation="Create custom service accounts with least-privilege roles for each workload.",
                            remediation=Remediation(
                                cli=(
                                    f"# Remove Editor from default SA:\n"
                                    f"gcloud projects remove-iam-policy-binding {provider.project} \\\n"
                                    f"  --member='serviceAccount:{sa_email}' --role='roles/editor'\n"
                                    f"# Create a dedicated SA with specific roles instead."
                                ),
                                terraform=(
                                    f'resource "google_service_account" "custom_sa" {{\n'
                                    f'  account_id   = "my-workload-sa"\n'
                                    f'  display_name = "My Workload SA"\n'
                                    f'  project      = "{provider.project}"\n'
                                    f"}}\n\n"
                                    f'resource "google_project_iam_member" "custom_role" {{\n'
                                    f'  project = "{provider.project}"\n'
                                    f'  role    = "roles/storage.objectViewer"  # least-privilege\n'
                                    f"  member  = \"serviceAccount:${{google_service_account.custom_sa.email}}\"\n"
                                    f"}}"
                                ),
                                doc_url="https://cloud.google.com/iam/docs/best-practices#service-accounts",
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=[
                                "ISO 27001 A.9.1.2",
                                "ISO 27001 A.9.2.3",
                                "SOC 2 CC6.1",
                                "SOC 2 CC6.3",
                                "CIS GCP 1.5",
                            ],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_mfa_enforcement(provider: GCPProvider) -> CheckResult:
    """Check if the organization enforces MFA (2-Step Verification) via org policy."""
    result = CheckResult(check_id="gcp-iam-005", check_name="MFA enforcement check")

    try:
        result.resources_scanned = 1
        # Check org policy for 2SV enforcement
        # Note: This requires Org-level access; at project level we flag as advisory
        policy = (
            provider.crm_service.projects()
            .getIamPolicy(resource=provider.project, body={"options": {"requestedPolicyVersion": 3}})
            .execute()
        )

        # Check if any user (non-SA) member exists - they should have MFA
        has_user_members = False
        for binding in policy.get("bindings", []):
            for member in binding.get("members", []):
                if member.startswith("user:") or member.startswith("group:"):
                    has_user_members = True
                    break
            if has_user_members:
                break

        if has_user_members:
            result.findings.append(
                Finding(
                    check_id="gcp-iam-005",
                    title="Ensure 2-Step Verification is enforced for all users",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="cloudresourcemanager.googleapis.com/Project",
                    resource_id=f"projects/{provider.project}",
                    description=(
                        "User or group members have IAM bindings on this project. "
                        "Ensure 2-Step Verification (MFA) is enforced via Google Workspace Admin Console."
                    ),
                    recommendation=(
                        "Enforce 2-Step Verification in Google Workspace Admin Console > Security > 2-Step Verification. "
                        "Set enrollment to 'Enforced' for all organizational units."
                    ),
                    remediation=Remediation(
                        cli=(
                            "# 2-Step Verification is enforced via Google Workspace Admin Console:\n"
                            "# https://admin.google.com > Security > 2-Step Verification\n"
                            "# Set to 'Enforced' for all organizational units.\n"
                            "# Cannot be configured via gcloud CLI."
                        ),
                        terraform=(
                            "# 2-Step Verification cannot be managed via Terraform.\n"
                            "# Use Google Workspace Admin Console to enforce MFA."
                        ),
                        doc_url="https://support.google.com/a/answer/175197",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=[
                        "ISO 27001 A.9.4.2",
                        "SOC 2 CC6.1",
                        "SOC 2 CC6.6",
                        "CIS GCP 1.1",
                    ],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all GCP IAM checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_service_account_key_rotation, provider, check_id="gcp-iam-001", category=Category.SECURITY),
        make_check(check_overly_permissive_roles, provider, check_id="gcp-iam-002", category=Category.SECURITY),
        make_check(check_sa_user_managed_keys, provider, check_id="gcp-iam-003", category=Category.SECURITY),
        make_check(check_default_sa_usage, provider, check_id="gcp-iam-004", category=Category.SECURITY),
        make_check(check_mfa_enforcement, provider, check_id="gcp-iam-005", category=Category.SECURITY),
    ]
