# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-03-06

### Security

- Bump Jinja2 minimum to >=3.1.6 (fixes CVE-2025-27516 sandbox breakout)
- Sanitize shell metacharacters in `--export-fixes` bash script output
- Set restrictive file permissions (700) on generated remediation scripts
- SHA-pin all GitHub Actions in CI and release workflows
- Dockerfile: non-root user, pinned base image digest, `--no-input` flag

### Added

- `make_check()` helper for consistent check registration with metadata
- `.gcp-auditor.example.yml` config template
- Pre-filtering of excluded checks before API calls (no wasted requests)

### Changed

- SARIF output: fixed `uriBaseId`, added `fullDescription` and `originalUriBaseIds`
- HTML report: light mode support, print CSS, ARIA labels, copyCode fix
- Markdown report: pipe escaping in table cells
- ASCII severity icons (fixes UnicodeEncodeError on Windows cp1250)

### Documentation

- Updated README for GCP focus
- Updated all documentation for new project ownership

## [0.5.0] - 2026-03-05

### Added

- `.gcp-auditor.yml` config file with suppressions (allowlist pattern)
- SARIF v2.1.0 output for GitHub Code Scanning integration
- Markdown report generator for PR comments
- `--format` flag (json, sarif, markdown, html)
- `--min-severity`, `--quiet`, `--service-account-key`, `--config` CLI flags
- `list-checks` command
- 4 environment variables: `GCP_AUDITOR_MIN_SEVERITY`, `GCP_AUDITOR_EXCLUDE_CHECKS`, `GCP_AUDITOR_REGIONS`, `GOOGLE_APPLICATION_CREDENTIALS`
- Exit codes: 0=clean, 1=findings, 2=errors

## [0.1.0] - 2026-03-03

### Added

- Initial release
- GCP provider with IAM, Storage, Compute Engine, Firewall checks
- CLI interface with `scan` and `version` commands
- Health score (0-100) based on finding severity
- HTML report with dark-mode design
- JSON output for CI/CD integration
- Docker image support
- Rich terminal UI with progress bar and color-coded findings

[Unreleased]: https://github.com/abdullahkamil/gcp-auditor/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/abdullahkamil/gcp-auditor/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/abdullahkamil/gcp-auditor/compare/v0.1.0...v0.5.0
[0.1.0]: https://github.com/abdullahkamil/gcp-auditor/releases/tag/v0.1.0
