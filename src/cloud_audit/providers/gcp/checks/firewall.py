"""GCP VPC Firewall security checks with ISO 27001 and SOC 2 compliance mappings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn
    from cloud_audit.providers.gcp.provider import GCPProvider

# Sensitive ports that should never be open to the internet
_SENSITIVE_PORTS = {
    "22": "SSH",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "1433": "MSSQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
}


def _port_in_range(port_str: str, port_to_check: str) -> bool:
    """Check if a port falls within a range string like '0-65535' or '22'."""
    if "-" in port_str:
        low, high = port_str.split("-", 1)
        return int(low) <= int(port_to_check) <= int(high)
    return port_str == port_to_check


def check_overly_permissive_firewall(provider: GCPProvider) -> CheckResult:
    """Check for firewall rules allowing unrestricted ingress on sensitive ports."""
    result = CheckResult(check_id="gcp-firewall-001", check_name="Overly permissive firewall rules")

    try:
        request = provider.compute_service.firewalls().list(project=provider.project)
        while request is not None:
            response = request.execute()
            for fw in response.get("items", []):
                result.resources_scanned += 1
                name = fw["name"]

                # Only check INGRESS rules
                if fw.get("direction", "INGRESS") != "INGRESS":
                    continue

                source_ranges = fw.get("sourceRanges", [])
                if "0.0.0.0/0" not in source_ranges:
                    continue

                for allowed in fw.get("allowed", []):
                    protocol = allowed.get("IPProtocol", "")
                    if protocol not in ("tcp", "udp", "all"):
                        continue

                    ports = allowed.get("ports", [])
                    # If no ports specified and protocol is tcp/udp/all, it means all ports
                    if not ports or protocol == "all":
                        result.findings.append(
                            Finding(
                                check_id="gcp-firewall-001",
                                title=f"Firewall '{name}' allows 0.0.0.0/0 on all {protocol} ports",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="compute.googleapis.com/Firewall",
                                resource_id=f"projects/{provider.project}/global/firewalls/{name}",
                                description=(
                                    f"Firewall rule '{name}' allows ingress from 0.0.0.0/0 on all "
                                    f"{protocol} ports. This exposes all services to the internet."
                                ),
                                recommendation="Restrict source ranges to known IPs/CIDRs and limit to required ports.",
                                remediation=Remediation(
                                    cli=(
                                        f"gcloud compute firewall-rules update {name} \\\n"
                                        f"  --source-ranges=10.0.0.0/8 \\\n"
                                        f"  --allow=tcp:443"
                                    ),
                                    terraform=(
                                        f'resource "google_compute_firewall" "{name}" {{\n'
                                        f'  name    = "{name}"\n'
                                        f'  network = "default"\n'
                                        f"  allow {{\n"
                                        f'    protocol = "tcp"\n'
                                        f'    ports    = ["443"]\n'
                                        f"  }}\n"
                                        f'  source_ranges = ["10.0.0.0/8"]  # Restrict to internal\n'
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/vpc/docs/firewalls",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.13.1.1",
                                    "ISO 27001 A.13.1.3",
                                    "SOC 2 CC6.1",
                                    "SOC 2 CC6.6",
                                    "CIS GCP 3.6",
                                ],
                            )
                        )
                        break

                    for port_range in ports:
                        for port, svc_name in _SENSITIVE_PORTS.items():
                            if _port_in_range(str(port_range), port):
                                result.findings.append(
                                    Finding(
                                        check_id="gcp-firewall-001",
                                        title=f"Firewall '{name}' exposes {svc_name} (port {port}) to 0.0.0.0/0",
                                        severity=Severity.CRITICAL if port in ("22", "3389") else Severity.HIGH,
                                        category=Category.SECURITY,
                                        resource_type="compute.googleapis.com/Firewall",
                                        resource_id=f"projects/{provider.project}/global/firewalls/{name}",
                                        description=(
                                            f"Firewall rule '{name}' allows {protocol}/{port} ({svc_name}) "
                                            f"from 0.0.0.0/0. This service should not be exposed to the internet."
                                        ),
                                        recommendation=f"Restrict {svc_name} access to specific source IPs or use IAP for SSH/RDP.",
                                        remediation=Remediation(
                                            cli=(
                                                f"gcloud compute firewall-rules update {name} \\\n"
                                                f"  --source-ranges=10.0.0.0/8"
                                            ),
                                            terraform=(
                                                f'resource "google_compute_firewall" "{name}" {{\n'
                                                f'  name    = "{name}"\n'
                                                f'  network = "default"\n'
                                                f"  allow {{\n"
                                                f'    protocol = "{protocol}"\n'
                                                f'    ports    = ["{port}"]\n'
                                                f"  }}\n"
                                                f'  source_ranges = ["10.0.0.0/8"]  # Restrict to internal\n'
                                                f"}}"
                                            ),
                                            doc_url="https://cloud.google.com/vpc/docs/using-firewalls",
                                            effort=Effort.LOW,
                                        ),
                                        compliance_refs=[
                                            "ISO 27001 A.13.1.1",
                                            "ISO 27001 A.13.1.3",
                                            "SOC 2 CC6.1",
                                            "SOC 2 CC6.6",
                                            "CIS GCP 3.6",
                                        ],
                                    )
                                )

            request = provider.compute_service.firewalls().list_next(
                previous_request=request, previous_response=response
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_default_network(provider: GCPProvider) -> CheckResult:
    """Check if the default network still exists."""
    result = CheckResult(check_id="gcp-firewall-002", check_name="Default network exists")

    try:
        result.resources_scanned = 1
        networks = provider.compute_service.networks().list(project=provider.project).execute()

        for network in networks.get("items", []):
            if network["name"] == "default":
                result.findings.append(
                    Finding(
                        check_id="gcp-firewall-002",
                        title="Default VPC network still exists",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="compute.googleapis.com/Network",
                        resource_id=f"projects/{provider.project}/global/networks/default",
                        description=(
                            "The default VPC network exists with pre-created firewall rules that allow "
                            "internal traffic, SSH, RDP, and ICMP. This creates unnecessary attack surface."
                        ),
                        recommendation="Delete the default network and create custom VPCs with least-privilege firewall rules.",
                        remediation=Remediation(
                            cli=(
                                "# Delete all default firewall rules first:\n"
                                f"gcloud compute firewall-rules list --filter='network=default' "
                                f"--project={provider.project} --format='value(name)' | "
                                f"xargs -I {{}} gcloud compute firewall-rules delete {{}} --project={provider.project} -q\n"
                                f"# Then delete the default network:\n"
                                f"gcloud compute networks delete default --project={provider.project} -q"
                            ),
                            terraform=(
                                "# Use google_compute_network with auto_create_subnetworks = false:\n"
                                'resource "google_compute_network" "custom_vpc" {\n'
                                '  name                    = "custom-vpc"\n'
                                "  auto_create_subnetworks = false\n"
                                "}"
                            ),
                            doc_url="https://cloud.google.com/vpc/docs/vpc#default-network",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[
                            "ISO 27001 A.13.1.1",
                            "ISO 27001 A.13.1.3",
                            "SOC 2 CC6.1",
                            "CIS GCP 3.1",
                        ],
                    )
                )
                break
    except Exception as e:
        result.error = str(e)

    return result


def check_flow_logs_enabled(provider: GCPProvider) -> CheckResult:
    """Check if VPC Flow Logs are enabled on all subnets."""
    result = CheckResult(check_id="gcp-firewall-003", check_name="VPC Flow Logs enabled")

    try:
        request = provider.compute_service.subnetworks().aggregatedList(project=provider.project)
        while request is not None:
            response = request.execute()
            for region, scoped_list in response.get("items", {}).items():
                subnets = scoped_list.get("subnetworks", [])
                for subnet in subnets:
                    result.resources_scanned += 1
                    name = subnet["name"]
                    region_name = subnet.get("region", "").split("/")[-1]

                    log_config = subnet.get("logConfig", {})
                    if not log_config.get("enable"):
                        result.findings.append(
                            Finding(
                                check_id="gcp-firewall-003",
                                title=f"Subnet '{name}' in '{region_name}' has VPC Flow Logs disabled",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="compute.googleapis.com/Subnetwork",
                                resource_id=f"projects/{provider.project}/regions/{region_name}/subnetworks/{name}",
                                region=region_name,
                                description=(
                                    f"Subnet '{name}' does not have VPC Flow Logs enabled. "
                                    f"Flow Logs are essential for network monitoring, forensics, and compliance."
                                ),
                                recommendation="Enable VPC Flow Logs on all production subnets.",
                                remediation=Remediation(
                                    cli=(
                                        f"gcloud compute networks subnets update {name} \\\n"
                                        f"  --region={region_name} \\\n"
                                        f"  --enable-flow-logs \\\n"
                                        f"  --logging-aggregation-interval=interval-5-sec \\\n"
                                        f"  --logging-flow-sampling=0.5"
                                    ),
                                    terraform=(
                                        f'resource "google_compute_subnetwork" "{name}" {{\n'
                                        f'  name   = "{name}"\n'
                                        f'  region = "{region_name}"\n'
                                        f"  log_config {{\n"
                                        f'    aggregation_interval = "INTERVAL_5_SEC"\n'
                                        f"    flow_sampling        = 0.5\n"
                                        f'    metadata             = "INCLUDE_ALL_METADATA"\n'
                                        f"  }}\n"
                                        f"}}"
                                    ),
                                    doc_url="https://cloud.google.com/vpc/docs/using-flow-logs",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=[
                                    "ISO 27001 A.12.4.1",
                                    "ISO 27001 A.13.1.1",
                                    "SOC 2 CC7.2",
                                    "SOC 2 CC7.3",
                                    "CIS GCP 3.8",
                                ],
                            )
                        )
            request = provider.compute_service.subnetworks().aggregatedList_next(
                previous_request=request, previous_response=response
            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: GCPProvider) -> list[CheckFn]:
    """Return all VPC/Firewall checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_overly_permissive_firewall, provider, check_id="gcp-firewall-001", category=Category.SECURITY),
        make_check(check_default_network, provider, check_id="gcp-firewall-002", category=Category.SECURITY),
        make_check(check_flow_logs_enabled, provider, check_id="gcp-firewall-003", category=Category.SECURITY),
    ]
