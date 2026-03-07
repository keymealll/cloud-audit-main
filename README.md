<h1 align="center">gcp-auditor</h1>

<p align="center">
  <strong>Open-source GCP security scanner. 30+ checks mapped to ISO 27001, SOC 2, and CIS GCP Benchmarks, each with a ready-to-use fix.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/gcp-auditor/"><img src="https://img.shields.io/pypi/v/gcp-auditor?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/gcp-auditor/"><img src="https://img.shields.io/pypi/pyversions/gcp-auditor?style=flat" alt="Python versions"></a>
  <a href="https://github.com/abdullahkamil/gcp-auditor/actions/workflows/ci.yml"><img src="https://github.com/abdullahkamil/gcp-auditor/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/abdullahkamil/gcp-auditor/main/assets/demo.gif" alt="gcp-auditor terminal demo" width="700">
</p>

gcp-auditor scans your Google Cloud Platform infrastructure for security misconfigurations and gives you a finding-by-finding remediation plan — gcloud CLI commands, Terraform HCL, and documentation links you can copy-paste to fix each issue.

It runs 30+ curated checks across IAM, Cloud Storage, Compute Engine, Cloud SQL, Cloud KMS, VPC Firewall, Cloud Logging, BigQuery, and GKE, mapped to ISO 27001, SOC 2, and CIS GCP Benchmark controls.

## Try it without a GCP account

```bash
pip install gcp-auditor
gcp-auditor demo
```

The `demo` command runs a simulated scan with sample data. You can see the output format, health score, and remediation details without any GCP credentials.

## Quick Start

```bash
pip install gcp-auditor
gcp-auditor scan --project my-project-id
```

That's it. Uses your default GCP Application Default Credentials. You'll get a health score and a list of findings in your terminal.

```bash
# Show remediation details for each finding
gcp-auditor scan --project my-project-id -R

# Specific regions
gcp-auditor scan --project my-project-id --regions us-central1,europe-west1

# Export all fixes as a runnable bash script
gcp-auditor scan --project my-project-id --export-fixes fixes.sh
```

## Who is this for

- **Small teams (1-10 people) without a dedicated security team** — get visibility into your GCP security posture without buying a platform
- **DevOps/SRE engineers running a pre-deploy check** — scan before shipping, catch misconfigurations early
- **Consultants doing client audits** — generate a professional HTML report you can hand to a client
- **Teams that need compliance evidence** — ISO 27001, SOC 2, and CIS GCP Benchmark mappings included in reports

## What it checks

30+ checks across IAM, Cloud Storage, Compute Engine, VPC Firewall, Cloud SQL, Cloud KMS, Cloud Logging, BigQuery, and GKE.

**By severity:** 5 Critical, 10 High, 12 Medium, 5+ Low.

Every check answers one question: *would an attacker exploit this?* If not, the check doesn't exist.

<details>
<summary>Full check list</summary>

### Security

| ID | Severity | Description |
|----|----------|-------------|
| `gcp-iam-001` | High | Service account with no key rotation |
| `gcp-iam-002` | Medium | Service account key older than 90 days |
| `gcp-iam-003` | Critical | Overly permissive IAM policy (roles/editor on project) |
| `gcp-storage-001` | Critical | Cloud Storage bucket publicly accessible |
| `gcp-storage-002` | High | Cloud Storage bucket without uniform access |
| `gcp-storage-003` | Medium | Cloud Storage bucket without versioning |
| `gcp-storage-004` | Medium | Cloud Storage bucket without lifecycle policy |
| `gcp-compute-001` | High | Compute instance with public IP |
| `gcp-compute-002` | Medium | Compute instance without OS Login |
| `gcp-compute-003` | Medium | Compute instance serial port enabled |
| `gcp-compute-004` | Low | Compute instance IP forwarding enabled |
| `gcp-firewall-001` | Critical | Firewall rule allows 0.0.0.0/0 on sensitive ports |
| `gcp-firewall-002` | High | Firewall rule allows 0.0.0.0/0 on SSH (port 22) |
| `gcp-firewall-003` | High | Firewall rule allows 0.0.0.0/0 on RDP (port 3389) |
| `gcp-sql-001` | Critical | Cloud SQL instance has public IP |
| `gcp-sql-002` | High | Cloud SQL instance without SSL enforcement |
| `gcp-sql-003` | Medium | Cloud SQL instance without automated backups |
| `gcp-kms-001` | Medium | KMS key without rotation |
| `gcp-kms-002` | High | KMS key with overly permissive IAM |
| `gcp-logging-001` | High | Logging sink not configured |
| `gcp-logging-002` | Medium | Log retention period too short |
| `gcp-bigquery-001` | Medium | BigQuery dataset is public |
| `gcp-gke-001` | Critical | GKE cluster has public control plane |
| `gcp-gke-002` | High | GKE cluster legacy ABAC enabled |
| `gcp-gke-003` | Medium | GKE cluster without workload identity |

### Cost

| ID | Severity | Description |
|----|----------|-------------|
| `gcp-storage-005` | Low | Cloud Storage bucket without lifecycle rules |
| `gcp-compute-005` | Low | Unattached persistent disk |

### Reliability

| ID | Severity | Description |
|----|----------|-------------|
| `gcp-storage-003` | Low | Cloud Storage bucket without versioning |
| `gcp-sql-003` | Medium | Cloud SQL without automated backups |
| `gcp-sql-004` | Low | Cloud SQL auto minor version upgrade disabled |

</details>

## Every finding includes a fix

This is what makes gcp-auditor different from most scanners. Run with `-R` to see remediation for each finding:

```
$ gcp-auditor scan --project my-project -R

  CRITICAL  Cloud Storage bucket publicly accessible
  Resource:   gs://public-data-bucket
  Compliance: ISO 27001 A.8.3, SOC 2 CC6.1, CIS GCP 5.1
  Effort:     LOW
  CLI:        gcloud storage buckets update gs://public-data-bucket --public-access-prevention=enforced
  Terraform:  resource "google_storage_bucket" "bucket" { ... }
  Docs:       https://cloud.google.com/storage/docs/public-access-prevention

  CRITICAL  Firewall rule allows 0.0.0.0/0 on port 22
  Resource:   default-allow-ssh
  Compliance: ISO 27001 A.13.1, SOC 2 CC6.6, CIS GCP 3.6
  Effort:     LOW
  CLI:        gcloud compute firewall-rules update default-allow-ssh --source-ranges=10.0.0.0/8
  Terraform:  resource "google_compute_firewall" "ssh" { ... }
```

Or export all fixes as a bash script:

```bash
gcp-auditor scan --project my-project --export-fixes fixes.sh
```

The script is commented and uses `set -e` — review it, uncomment what you want to apply, and run.

## Reports

<p align="center">
  <img src="https://raw.githubusercontent.com/abdullahkamil/gcp-auditor/main/assets/report-preview.png" alt="gcp-auditor HTML report" width="700">
</p>

```bash
# HTML report (dark-mode, self-contained, client-ready)
gcp-auditor scan --project my-project --format html --output report.html

# JSON
gcp-auditor scan --project my-project --format json --output report.json

# SARIF (GitHub Code Scanning integration)
gcp-auditor scan --project my-project --format sarif --output results.sarif

# Markdown (for PR comments)
gcp-auditor scan --project my-project --format markdown --output report.md
```

Format is auto-detected from file extension when using `--output`.

## Installation

### pip (recommended)

```bash
pip install gcp-auditor
```

### pipx (isolated environment)

```bash
pipx install gcp-auditor
```

### From source

```bash
git clone https://github.com/abdullahkamil/gcp-auditor.git
cd gcp-auditor
pip install -e "."
```

## Usage

```bash
# Scan all enabled regions
gcp-auditor scan --project my-project --regions all

# Filter by category
gcp-auditor scan --project my-project --categories security,cost

# Filter by minimum severity
gcp-auditor scan --project my-project --min-severity high

# Use service account key
gcp-auditor scan --project my-project --service-account-key sa-key.json

# Quiet mode (exit code only - for CI/CD)
gcp-auditor scan --project my-project --quiet

# List all available checks
gcp-auditor list-checks
gcp-auditor list-checks --categories security
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (after suppressions and severity filter) |
| 1 | Findings detected |
| 2 | Scan error (bad credentials, invalid config) |

### Configuration file

Create `.gcp-auditor.yml` in your project root:

```yaml
provider: gcp
project: my-project-id
regions:
  - us-central1
  - europe-west1
min_severity: medium
exclude_checks:
  - gcp-storage-005
suppressions:
  - check_id: gcp-firewall-001
    resource_id: my-allowed-rule
    reason: "Intentionally open for load balancer"
    accepted_by: "admin@example.com"
    expires: "2026-12-31"
```

Auto-detected from the current directory. Override with `--config path/to/.gcp-auditor.yml`.

**Precedence:** CLI flags > environment variables > config file > defaults.

### Environment variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GCP_AUDITOR_REGIONS` | Comma-separated regions | `us-central1,europe-west1` |
| `GCP_AUDITOR_MIN_SEVERITY` | Minimum severity filter | `high` |
| `GCP_AUDITOR_EXCLUDE_CHECKS` | Comma-separated check IDs to skip | `gcp-storage-005` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account key | `/path/to/key.json` |

## CI/CD Integration

### GitHub Actions

```yaml
name: GCP Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  id-token: write
  contents: read
  security-events: write
  actions: read
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install gcp-auditor
        run: pip install gcp-auditor

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v2

      - name: Scan (SARIF)
        continue-on-error: true
        run: gcp-auditor scan --project ${{ secrets.GCP_PROJECT }} --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: gcp-auditor

      - name: Scan (Markdown)
        if: github.event_name == 'pull_request'
        continue-on-error: true
        run: gcp-auditor scan --project ${{ secrets.GCP_PROJECT }} --format markdown --output report.md

      - name: Post PR comment
        if: github.event_name == 'pull_request'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: report.md
```

This gives you findings in the GitHub Security tab (via SARIF) and a Markdown summary on every PR.

## GCP Permissions

gcp-auditor requires **read-only** access. Assign the GCP `Viewer` role (`roles/viewer`) or specific service roles:

```bash
# Grant viewer role to service account
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditor@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

gcp-auditor never modifies your infrastructure. It only makes read API calls.

## Health Score

Starts at 100, decreases per finding:

| Severity | Points deducted |
|----------|----------------|
| Critical | -20 |
| High | -10 |
| Medium | -5 |
| Low | -2 |

80+ is good, 50-79 needs attention, below 50 requires immediate action.

## Alternatives

There are mature tools in this space. Pick the right one for your use case:

- **[Prowler](https://github.com/prowler-cloud/prowler)** — 500+ checks across AWS/Azure/GCP, full CIS benchmark coverage, auto-remediation. The most comprehensive open-source scanner.
- **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** — Multi-cloud scanner with an interactive HTML report.
- **[Trivy](https://github.com/aquasecurity/trivy)** — Container, IaC, and cloud scanner. Strong on containers, growing cloud coverage.
- **[Forseti Security](https://forsetisecurity.org/)** — GCP-native security toolkit from Google.
- **[GCP Security Command Center](https://cloud.google.com/security-command-center)** — Native GCP service with continuous monitoring.

gcp-auditor fills a specific niche: a focused GCP audit with copy-paste remediation for each finding. If you need full CIS compliance coverage, Prowler is the better choice. If you need a quick scan that tells you exactly how to fix each issue, gcp-auditor is built for that.

## Roadmap

- **v0.7.0** — Additional GKE, Cloud Run, and Cloud Functions checks
- **v1.0.0** — Enhanced HTML reports, scan diff/compare, 40+ total checks

See [ROADMAP.md](ROADMAP.md) for details.

## Development

```bash
git clone https://github.com/abdullahkamil/gcp-auditor.git
cd gcp-auditor
pip install -e ".[dev]"

pytest -v                          # tests
ruff check src/ tests/             # lint
ruff format --check src/ tests/    # format
mypy src/                          # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new check.

## License

[MIT](LICENSE) — Abdullah Kamil
