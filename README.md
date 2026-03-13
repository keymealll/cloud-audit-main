<h1 align="center">cloud-audit</h1>

<p align="center">
  <strong>Fast, opinionated GCP security scanner. Curated checks. Zero noise. Copy-paste fixes.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/v/cloud-audit?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/pyversions/cloud-audit?style=flat" alt="Python versions"></a>
  <a href="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml"><img src="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
</p>

## Why cloud-audit?

- **Curated, high-signal checks** - every check catches something an attacker would actually exploit
- **Every finding = copy-paste fix** - `gcloud` CLI command + Terraform HCL + docs link, ready to go
- **12 seconds, not 12 minutes** - scan completes before your coffee gets cold
- **Zero configuration** - `pip install cloud-audit && cloud-audit scan` gives results immediately
- **Beautiful reports** - dark-mode HTML report you can send to your manager or client

## Every Finding = A Fix

This is what makes cloud-audit different. Run with `-R` and every finding includes a ready-to-use remediation:

```
$ cloud-audit scan -R

  CRITICAL  Default compute service account has Editor role
  Resource:   projects/my-project/serviceAccounts/default
  Compliance: CIS GCP 4.1
  Effort:     LOW
  CLI:        gcloud projects remove-iam-policy-binding ...
  Terraform:  resource "google_project_iam_binding" "default" { ... }
  Docs:       https://cloud.google.com/iam/docs/...
```

Export all fixes as a bash script: `cloud-audit scan --export-fixes fixes.sh`

## Quick Start

```bash
pip install cloud-audit
cloud-audit scan
```

## What It Checks

### Security

| Check | ID | Severity | Description |
|-------|----|----------|-------------|
| UBLA disabled | `gcp-storage-001` | High | Storage bucket without Uniform Bucket-Level Access enabled |
| Default SA Editor | `gcp-iam-001` | Critical | Default Compute Engine service account has the Editor role |
| Old SA Keys | `gcp-iam-002` | Medium | User-managed service account keys older than 90 days |
| Public VM IPs | `gcp-compute-001` | Critical | Compute instance with a public IP address |

## Usage

```bash
# Scan with default GCP application credentials
cloud-audit scan

# Specific GCP project
cloud-audit scan --project my-gcp-project

# Filter by category
cloud-audit scan --categories security,cost

# Show remediation details (CLI commands, Terraform, docs)
cloud-audit scan -R

# Export all fix commands as a dry-run bash script
cloud-audit scan --export-fixes fixes.sh

# Generate HTML report
cloud-audit scan --output report.html

# Generate JSON report (for CI/CD pipelines)
cloud-audit scan --output report.json
```

## GCP Permissions

cloud-audit requires **read-only** access. Attach the Security Reviewer (`roles/iam.securityReviewer`) or Viewer (`roles/viewer`) role to your service account or user.

You can authenticate using Application Default Credentials:
```bash
gcloud auth application-default login
```

cloud-audit **never modifies** your infrastructure. It only makes read API calls.

## Health Score

The health score starts at 100 and decreases based on findings:

| Severity | Points deducted |
|----------|----------------|
| Critical | -20 |
| High | -10 |
| Medium | -5 |
| Low | -2 |

## Development

```bash
# Clone and install in development mode
git clone https://github.com/keymealll/cloud-audit-main.git
cd cloud-audit
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint and format
ruff check src/ tests/
ruff format --check src/ tests/

# Type check
mypy src/
```

## License

[MIT](LICENSE) - Abdullah Kamil
