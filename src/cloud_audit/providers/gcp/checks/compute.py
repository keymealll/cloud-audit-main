"""GCP Compute Engine security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider


def check_public_ip_instances(provider: GCPProvider) -> CheckResult:
    """Check for Compute Engine instances with external (public) IP addresses."""
    result = CheckResult(check_id="gcp-compute-001", check_name="Instances with public IPs")

    try:
        # Aggregate across all zones in configured regions
        request = provider.compute_service.instances().aggregatedList(project=provider.project)
        while request is not None:
            response = request.execute()
            for zone, scoped_list in response.get("items", {}).items():
                instances = scoped_list.get("instances", [])
                for instance in instances:
                    result.resources_scanned += 1
                    name = instance["name"]
                    zone_name = instance["zone"].split("/")[-1]

                    for iface in instance.get("networkInterfaces", []):
                        access_configs = iface.get("accessConfigs", [])
                        for ac in access_configs:
                            if ac.get("natIP"):
                                result.findings.append(
                                    Finding(
                                        check_id="gcp-compute-001",
                                        title=f"Instance '{name}' has public IP {ac['natIP']}",
                                        severity=Severity.HIGH,
                                        category=Category.SECURITY,
                                        resource_type="compute.googleapis.com/Instance",
                                        resource_id=f"projects/{provider.project}/zones/{zone_name}/instances/{name}",
                                        region=zone_name,
                                        description=(
                                            f"Compute instance '{name}' in zone '{zone_name}' has external IP "
                                            f"{ac['natIP']}. Instances with public IPs are directly exposed to the internet."
                                        ),
                                        recommendation="Use Cloud NAT or IAP for egress/ingress instead of public IPs.",
                                        remediation=Remediation(
                                            cli=(
                                                f"# Remove external IP:\n"
                                                f"gcloud compute instances delete-access-config {name} \\\n"
                                                f"  --zone={zone_name} \\\n"
                                                f"  --access-config-name='{ac.get('name', 'External NAT')}'"
                                            ),
                                            terraform=(
                                                f'resource "google_compute_instance" "{name}" {{\n'
                                                f"  # Remove access_config block to remove public IP\n"
                                                f"  network_interface {{\n"
                                                f'    network = "default"\n'
                                                f"    # access_config {{}} # REMOVE THIS\n"
                                                f"  }}\n"
                                                f"}}"
                                            ),
                                            doc_url="https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
                                            effort=Effort.MEDIUM,
                                        ),
                                        compliance_refs=[
                                            "ISO 27001 A.13.1.1",
                                            "ISO 27001 A.13.1.3",
                                            "SOC 2 CC6.1",
                                            "SOC 2 CC6.6",
                                            "CIS GCP 4.9",
                                        ],
                                    )
                                )
                                break  # One finding per instance
            request = provider.compute_service.instances().aggregatedList_next(
                previous_request=request, previous_response=response
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_disk_encryption(provider: GCPProvider) -> CheckResult:
    """Check if persistent disks use CMEK encryption."""
    result = CheckResult(check_id="gcp-compute-002", check_name="Disk CMEK encryption")

    try:
        request = provider.compute_service.disks().aggregatedList(project=provider.project)
        while request is not None:
            response = request.execute()
            for zone, scoped_list in response.get("items", {}).items():
                disks = scoped_list.get("disks", [])
                for disk in disks:
                    result.resources_scanned += 1
                    name = disk["name"]
                    zone_name = disk.get("zone", "").split("/")[-1]

                    encryption = disk.get("diskEncryptionKey")
                    if not encryption or not encryption.get("kmsKeyName"):
                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-002",
                                title=f"Disk '{name}' is not encrypted with CMEK",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="compute.googleapis.com/Disk",
                                resource_id=f"projects/{provider.project}/zones/{zone_name}/disks/{name}",
                                region=zone_name,
                                description=(
                                    f"Disk '{name}' uses Google-managed encryption (default). "
                                    f"CMEK provides better control over key management and rotation."
                                ),
                                recommendation="Encrypt disks with Customer-Managed Encryption Keys (CMEK) for sensitive data.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Create a new disk with CMEK (cannot retroactively encrypt):\n"
                                        f"gcloud compute disks create {name}-cmek \\\n"
                                        f"  --zone={zone_name} \\\n"
                                        f"  --source-disk={name} \\\n"
                                        f"  --kms-key=projects/{provider.project}/locations/LOCATION/keyRings/RING/cryptoKeys/KEY"
                                    ),
                                    terraform=(
                                        f'resource "google_compute_disk" "{name}" {{\n'
                                        f'  name = "{name}"\n'
                                        f"  disk_encryption_key {{\n"
                                        f"    kms_key_self_link = google_kms_crypto_key.key.id\n"
                                        f"  }}\n"
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/compute/docs/disks/customer-managed-encryption",
                                    effort=Effort.HIGH,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.10.1.1",
                                    "ISO 27001 A.10.1.2",
                                    "SOC 2 CC6.1",
                                    "SOC 2 CC6.7",
                                    "CIS GCP 4.7",
                                ],
                            )
                        )
            request = provider.compute_service.disks().aggregatedList_next(
                previous_request=request, previous_response=response
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_serial_port_disabled(provider: GCPProvider) -> CheckResult:
    """Check if serial port access is disabled on instances."""
    result = CheckResult(check_id="gcp-compute-003", check_name="Serial port access disabled")

    try:
        request = provider.compute_service.instances().aggregatedList(project=provider.project)
        while request is not None:
            response = request.execute()
            for zone, scoped_list in response.get("items", {}).items():
                instances = scoped_list.get("instances", [])
                for instance in instances:
                    result.resources_scanned += 1
                    name = instance["name"]
                    zone_name = instance["zone"].split("/")[-1]

                    metadata = instance.get("metadata", {})
                    items = {i["key"]: i["value"] for i in metadata.get("items", [])}

                    if items.get("serial-port-enable", "").lower() == "true":
                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-003",
                                title=f"Instance '{name}' has serial port access enabled",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="compute.googleapis.com/Instance",
                                resource_id=f"projects/{provider.project}/zones/{zone_name}/instances/{name}",
                                region=zone_name,
                                description=(
                                    f"Instance '{name}' has serial port access enabled. "
                                    f"This provides a potential backdoor for attackers."
                                ),
                                recommendation="Disable serial port access unless required for debugging.",
                                remediation=Remediation(
                                    cli=(
                                        f"gcloud compute instances add-metadata {name} \\\n"
                                        f"  --zone={zone_name} \\\n"
                                        f"  --metadata=serial-port-enable=false"
                                    ),
                                    terraform=(
                                        f'resource "google_compute_instance" "{name}" {{\n'
                                        f"  metadata = {{\n"
                                        f'    serial-port-enable = "false"\n'
                                        f"  }}\n"
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.9.4.1",
                                    "SOC 2 CC6.1",
                                    "CIS GCP 4.5",
                                ],
                            )
                        )
            request = provider.compute_service.instances().aggregatedList_next(
                previous_request=request, previous_response=response
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_os_login_enabled(provider: GCPProvider) -> CheckResult:
    """Check if OS Login is enabled at project level."""
    result = CheckResult(check_id="gcp-compute-004", check_name="OS Login enabled")

    try:
        result.resources_scanned = 1
        project_info = provider.compute_service.projects().get(project=provider.project).execute()

        common_metadata = project_info.get("commonInstanceMetadata", {})
        items = {i["key"]: i["value"] for i in common_metadata.get("items", [])}

        if items.get("enable-oslogin", "").lower() != "true":
            result.findings.append(
                Finding(
                    check_id="gcp-compute-004",
                    title="OS Login is not enabled at project level",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="compute.googleapis.com/Project",
                    resource_id=f"projects/{provider.project}",
                    description=(
                        "OS Login is not enabled project-wide. Without OS Login, SSH key management "
                        "relies on metadata-based keys which are harder to audit and rotate."
                    ),
                    recommendation="Enable OS Login to centralize SSH access management via IAM.",
                    remediation=Remediation(
                        cli=(
                            f"gcloud compute project-info add-metadata \\\n"
                            f"  --project={provider.project} \\\n"
                            f"  --metadata enable-oslogin=TRUE"
                        ),
                        terraform=(
                            f'resource "google_compute_project_metadata" "os_login" {{\n'
                            f'  project = "{provider.project}"\n'
                            f"  metadata = {{\n"
                            f'    enable-oslogin = "TRUE"\n'
                            f"  }}\n"
                            f"}}"
                        ),
                        doc_url="https://cloud.google.com/compute/docs/instances/managing-instance-access",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=[
                        "ISO 27001 A.9.1.2",
                        "ISO 27001 A.9.2.1",
                        "SOC 2 CC6.1",
                        "SOC 2 CC6.2",
                        "CIS GCP 4.4",
                    ],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_shielded_vm(provider: GCPProvider) -> CheckResult:
    """Check if instances use Shielded VM features."""
    result = CheckResult(check_id="gcp-compute-005", check_name="Shielded VM enabled")

    try:
        request = provider.compute_service.instances().aggregatedList(project=provider.project)
        while request is not None:
            response = request.execute()
            for zone, scoped_list in response.get("items", {}).items():
                instances = scoped_list.get("instances", [])
                for instance in instances:
                    result.resources_scanned += 1
                    name = instance["name"]
                    zone_name = instance["zone"].split("/")[-1]

                    shielded = instance.get("shieldedInstanceConfig", {})
                    if not shielded.get("enableSecureBoot") or not shielded.get("enableVtpm"):
                        result.findings.append(
                            Finding(
                                check_id="gcp-compute-005",
                                title=f"Instance '{name}' does not have Shielded VM fully enabled",
                                severity=Severity.LOW,
                                category=Category.SECURITY,
                                resource_type="compute.googleapis.com/Instance",
                                resource_id=f"projects/{provider.project}/zones/{zone_name}/instances/{name}",
                                region=zone_name,
                                description=(
                                    f"Instance '{name}' does not have Secure Boot and/or vTPM enabled. "
                                    f"Shielded VM protects against rootkits and boot-level attacks."
                                ),
                                recommendation="Enable Shielded VM with Secure Boot and vTPM.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Stop the instance first:\n"
                                        f"gcloud compute instances stop {name} --zone={zone_name}\n"
                                        f"gcloud compute instances update {name} --zone={zone_name} \\\n"
                                        f"  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring\n"
                                        f"gcloud compute instances start {name} --zone={zone_name}"
                                    ),
                                    terraform=(
                                        f'resource "google_compute_instance" "{name}" {{\n'
                                        f"  shielded_instance_config {{\n"
                                        f"    enable_secure_boot          = true\n"
                                        f"    enable_vtpm                 = true\n"
                                        f"    enable_integrity_monitoring = true\n"
                                        f"  }}\n"
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/compute/shielded-vm/docs/shielded-vm",
                                    effort=Effort.MEDIUM,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.12.2.1",
                                    "SOC 2 CC6.1",
                                    "SOC 2 CC7.1",
                                    "CIS GCP 4.8",
                                ],
                            )
                        )
            request = provider.compute_service.instances().aggregatedList_next(
                previous_request=request, previous_response=response
            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all Compute Engine checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_public_ip_instances, provider, check_id="gcp-compute-001", category=Category.SECURITY),
        make_check(check_disk_encryption, provider, check_id="gcp-compute-002", category=Category.SECURITY),
        make_check(check_serial_port_disabled, provider, check_id="gcp-compute-003", category=Category.SECURITY),
        make_check(check_os_login_enabled, provider, check_id="gcp-compute-004", category=Category.SECURITY),
        make_check(check_shielded_vm, provider, check_id="gcp-compute-005", category=Category.SECURITY),
    ]
