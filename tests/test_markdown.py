"""Tests for Markdown report generator."""

from __future__ import annotations

from cloud_audit.models import (
    Category,
    CheckResult,
    Finding,
    ScanReport,
    Severity,
)
from cloud_audit.reports.markdown import generate_markdown


def _make_report(findings: list[Finding] | None = None) -> ScanReport:
    """Create a minimal ScanReport for testing."""
    if findings is None:
        findings = [
            Finding(
                check_id="aws-iam-001",
                title="Root account without MFA",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                resource_type="AWS::IAM::User",
                resource_id="root",
                region="global",
                description="Root account does not have MFA enabled.",
                recommendation="Enable MFA.",
                compliance_refs=["CIS 1.5"],
            ),
            Finding(
                check_id="aws-s3-003",
                title="Bucket without versioning",
                severity=Severity.LOW,
                category=Category.SECURITY,
                resource_type="AWS::S3::Bucket",
                resource_id="my-bucket",
                region="global",
                description="No versioning.",
                recommendation="Enable versioning.",
            ),
        ]
    report = ScanReport(provider="aws", account_id="123456789012", regions=["eu-central-1"])
    report.results.append(
        CheckResult(
            check_id="aws-test",
            check_name="Test",
            findings=findings,
            resources_scanned=10,
        )
    )
    report.compute_summary()
    return report


def test_markdown_has_header() -> None:
    """Markdown starts with report header."""
    md = generate_markdown(_make_report())
    assert "# gcp-auditor scan report" in md


def test_markdown_has_provider_info() -> None:
    """Markdown includes provider, account, regions."""
    md = generate_markdown(_make_report())
    assert "AWS" in md
    assert "123456789012" in md
    assert "eu-central-1" in md


def test_markdown_has_summary_table() -> None:
    """Markdown has summary section with metrics."""
    md = generate_markdown(_make_report())
    assert "## Summary" in md
    assert "Resources scanned" in md
    assert "Total findings" in md


def test_markdown_has_severity_section() -> None:
    """Markdown lists findings by severity."""
    md = generate_markdown(_make_report())
    assert "## Findings by severity" in md
    assert "CRITICAL" in md


def test_markdown_has_findings_table() -> None:
    """Markdown has findings table with columns."""
    md = generate_markdown(_make_report())
    assert "| Severity | Check | Region | Resource | Title |" in md
    assert "aws-iam-001" in md
    assert "aws-s3-003" in md


def test_markdown_findings_sorted_by_severity() -> None:
    """CRITICAL comes before LOW in findings table."""
    md = generate_markdown(_make_report())
    crit_pos = md.index("**CRITICAL**")
    low_pos = md.index("**LOW**")
    assert crit_pos < low_pos


def test_markdown_has_cis_section() -> None:
    """CIS refs are listed in their own section."""
    md = generate_markdown(_make_report())
    assert "## CIS Benchmark coverage" in md
    assert "CIS 1.5" in md


def test_markdown_has_footer() -> None:
    """Markdown ends with gcp-auditor link."""
    md = generate_markdown(_make_report())
    assert "gcp-auditor" in md
    assert "github.com/abdullahkamil/gcp-auditor" in md


def test_markdown_empty_findings() -> None:
    """Report with no findings says so."""
    md = generate_markdown(_make_report(findings=[]))
    assert "No issues found" in md


def test_markdown_long_resource_id_truncated() -> None:
    """Long resource IDs are truncated in the table."""
    findings = [
        Finding(
            check_id="aws-test-001",
            title="Test finding",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            resource_type="AWS::Test::Resource",
            resource_id="a" * 60,
            region="eu-central-1",
            description="Test.",
            recommendation="Fix.",
        ),
    ]
    md = generate_markdown(_make_report(findings=findings))
    # Resource should be truncated to 40 chars + "..."
    assert "a" * 40 + "..." in md
