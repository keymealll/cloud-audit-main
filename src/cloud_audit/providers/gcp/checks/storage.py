"""GCP Cloud Storage security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider


def _tf_name(name: str) -> str:
    """Sanitize a resource name for use as a Terraform identifier."""
    sanitized = name.replace(".", "_").replace("-", "_")
    if sanitized and sanitized[0].isdigit():
        sanitized = f"bucket_{sanitized}"
    return sanitized


def check_public_buckets(provider: GCPProvider) -> CheckResult:
    """Check for GCS buckets that are publicly accessible."""
    result = CheckResult(check_id="gcp-storage-001", check_name="Public GCS buckets")

    try:
        buckets = list(provider.storage_client.list_buckets())
        for bucket in buckets:
            result.resources_scanned += 1
            name = bucket.name

            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    members = binding.get("members", set())
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public_type = "allUsers" if "allUsers" in members else "allAuthenticatedUsers"
                        result.findings.append(
                            Finding(
                                check_id="gcp-storage-001",
                                title=f"GCS bucket '{name}' is publicly accessible via {public_type}",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="storage.googleapis.com/Bucket",
                                resource_id=f"gs://{name}",
                                description=(
                                    f"Bucket '{name}' grants access to '{public_type}' with role "
                                    f"'{binding.get('role', 'unknown')}'. This exposes data to the internet."
                                ),
                                recommendation="Remove public access unless the bucket explicitly hosts public content.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Remove public access:\n"
                                        f"gsutil iam ch -d {public_type} gs://{name}\n"
                                        f"# Or set uniform bucket-level access:\n"
                                        f"gcloud storage buckets update gs://{name} --uniform-bucket-level-access"
                                    ),
                                    terraform=(
                                        f'resource "google_storage_bucket_iam_member" "remove_public" {{\n'
                                        f"  # Remove this resource to revoke public access\n"
                                        f'  bucket = "{name}"\n'
                                        f'  role   = "{binding.get("role", "roles/storage.objectViewer")}"\n'
                                        f'  member = "{public_type}"\n'
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/storage/docs/access-control/making-data-public",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.8.2.3",
                                    "ISO 27001 A.13.1.3",
                                    "SOC 2 CC6.1",
                                    "SOC 2 CC6.6",
                                    "CIS GCP 5.1",
                                ],
                            )
                        )
                        break  # One finding per bucket is enough
            except Exception:
                continue
    except Exception as e:
        result.error = str(e)

    return result


def check_uniform_bucket_access(provider: GCPProvider) -> CheckResult:
    """Check if buckets use uniform bucket-level access."""
    result = CheckResult(check_id="gcp-storage-002", check_name="Uniform bucket-level access")

    try:
        buckets = list(provider.storage_client.list_buckets())
        for bucket in buckets:
            result.resources_scanned += 1
            name = bucket.name

            uba = bucket.iam_configuration.get("uniformBucketLevelAccess", {})
            if not uba.get("enabled", False):
                result.findings.append(
                    Finding(
                        check_id="gcp-storage-002",
                        title=f"GCS bucket '{name}' does not use uniform bucket-level access",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="storage.googleapis.com/Bucket",
                        resource_id=f"gs://{name}",
                        description=(
                            f"Bucket '{name}' uses fine-grained ACLs instead of uniform bucket-level access. "
                            f"ACLs are harder to audit and more error-prone."
                        ),
                        recommendation="Enable uniform bucket-level access to simplify permissions management.",
                        remediation=Remediation(
                            cli=f"gcloud storage buckets update gs://{name} --uniform-bucket-level-access",
                            terraform=(
                                f'resource "google_storage_bucket" "{_tf_name(name)}" {{\n'
                                f'  name     = "{name}"\n'
                                f"  uniform_bucket_level_access = true\n"
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/storage/docs/uniform-bucket-level-access",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.9.1.2",
                            "ISO 27001 A.9.4.1",
                            "SOC 2 CC6.1",
                            "CIS GCP 5.2",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_bucket_encryption(provider: GCPProvider) -> CheckResult:
    """Check if GCS buckets use Customer-Managed Encryption Keys (CMEK)."""
    result = CheckResult(check_id="gcp-storage-003", check_name="GCS bucket CMEK encryption")

    try:
        buckets = list(provider.storage_client.list_buckets())
        for bucket in buckets:
            result.resources_scanned += 1
            name = bucket.name

            encryption = bucket._properties.get("encryption", {})
            if not encryption.get("defaultKmsKeyName"):
                result.findings.append(
                    Finding(
                        check_id="gcp-storage-003",
                        title=f"GCS bucket '{name}' does not use CMEK encryption",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="storage.googleapis.com/Bucket",
                        resource_id=f"gs://{name}",
                        description=(
                            f"Bucket '{name}' uses Google-managed encryption keys (default). "
                            f"CMEK provides additional control over key lifecycle and access."
                        ),
                        recommendation="Enable CMEK for buckets containing sensitive data.",
                        remediation=Remediation(
                            cli=(
                                f"gcloud storage buckets update gs://{name} \\\n"
                                f"  --default-encryption-key=projects/{provider.project}/"
                                f"locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME"
                            ),
                            terraform=(
                                f'resource "google_storage_bucket" "{_tf_name(name)}" {{\n'
                                f'  name     = "{name}"\n'
                                f"  encryption {{\n"
                                f"    default_kms_key_name = google_kms_crypto_key.key.id\n"
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/storage/docs/encryption/customer-managed-keys",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.10.1.1",
                            "ISO 27001 A.10.1.2",
                            "SOC 2 CC6.1",
                            "SOC 2 CC6.7",
                            "CIS GCP 5.3",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_bucket_logging(provider: GCPProvider) -> CheckResult:
    """Check if GCS buckets have access logging enabled."""
    result = CheckResult(check_id="gcp-storage-004", check_name="GCS bucket access logging")

    try:
        buckets = list(provider.storage_client.list_buckets())
        for bucket in buckets:
            result.resources_scanned += 1
            name = bucket.name

            logging_config = bucket._properties.get("logging")
            if not logging_config or not logging_config.get("logBucket"):
                result.findings.append(
                    Finding(
                        check_id="gcp-storage-004",
                        title=f"GCS bucket '{name}' does not have access logging enabled",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="storage.googleapis.com/Bucket",
                        resource_id=f"gs://{name}",
                        description=(
                            f"Bucket '{name}' has no access logging configured. "
                            f"Without logging, access attempts cannot be audited."
                        ),
                        recommendation="Enable access logging to track requests to the bucket.",
                        remediation=Remediation(
                            cli=(
                                f"gcloud storage buckets update gs://{name} \\\n"
                                f"  --log-bucket=gs://{name}-logs --log-object-prefix=access-logs/"
                            ),
                            terraform=(
                                f'resource "google_storage_bucket" "{_tf_name(name)}" {{\n'
                                f'  name = "{name}"\n'
                                f"  logging {{\n"
                                f'    log_bucket        = "{name}-logs"\n'
                                f'    log_object_prefix = "access-logs/"\n'
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/storage/docs/access-logs",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.12.4.1",
                            "ISO 27001 A.12.4.3",
                            "SOC 2 CC7.2",
                            "SOC 2 CC7.3",
                            "CIS GCP 5.3",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_bucket_versioning(provider: GCPProvider) -> CheckResult:
    """Check if GCS buckets have versioning enabled."""
    result = CheckResult(check_id="gcp-storage-005", check_name="GCS bucket versioning")

    try:
        buckets = list(provider.storage_client.list_buckets())
        for bucket in buckets:
            result.resources_scanned += 1
            name = bucket.name

            if not bucket.versioning_enabled:
                result.findings.append(
                    Finding(
                        check_id="gcp-storage-005",
                        title=f"GCS bucket '{name}' does not have versioning enabled",
                        severity=Severity.LOW,
                        category=Category.RELIABILITY,
                        resource_type="storage.googleapis.com/Bucket",
                        resource_id=f"gs://{name}",
                        description=(
                            f"Bucket '{name}' does not have object versioning enabled. "
                            f"Without versioning, deleted or overwritten objects cannot be recovered."
                        ),
                        recommendation="Enable object versioning to protect against accidental deletion or overwrites.",
                        remediation=Remediation(
                            cli=f"gcloud storage buckets update gs://{name} --versioning",
                            terraform=(
                                f'resource "google_storage_bucket" "{_tf_name(name)}" {{\n'
                                f'  name = "{name}"\n'
                                f"  versioning {{\n"
                                f"    enabled = true\n"
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url="https://cloud.google.com/storage/docs/object-versioning",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.12.3.1",
                            "SOC 2 CC7.5",
                            "SOC 2 A1.2",
                        ],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all GCS storage checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_public_buckets, provider, check_id="gcp-storage-001", category=Category.SECURITY),
        make_check(check_uniform_bucket_access, provider, check_id="gcp-storage-002", category=Category.SECURITY),
        make_check(check_bucket_encryption, provider, check_id="gcp-storage-003", category=Category.SECURITY),
        make_check(check_bucket_logging, provider, check_id="gcp-storage-004", category=Category.SECURITY),
        make_check(check_bucket_versioning, provider, check_id="gcp-storage-005", category=Category.RELIABILITY),
    ]
