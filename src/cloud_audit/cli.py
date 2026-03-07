"""CLI interface for gcp-auditor."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloud_audit import __version__
from cloud_audit.models import Finding, ScanReport, Severity

app = typer.Typer(
    name="gcp-auditor",
    help="Scan your GCP infrastructure for security issues. ISO 27001 and SOC 2 compliance.",
    no_args_is_help=True,
)
console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "x",
    Severity.HIGH: "x",
    Severity.MEDIUM: "!",
    Severity.LOW: "o",
    Severity.INFO: "i",
}


def _print_summary(report: ScanReport, suppressed_count: int = 0) -> None:
    """Print a rich summary of the scan results to the console."""
    s = report.summary
    all_errored = s.checks_errored > 0 and s.checks_passed == 0 and s.checks_failed == 0

    # If all checks errored, show error banner instead of fake score
    if all_errored:
        console.print()
        console.print(
            Panel(
                "[bold red]SCAN FAILED[/bold red]\n\nAll checks returned errors. No resources were scanned.",
                title="[bold red]Error[/bold red]",
                border_style="red",
                width=60,
            )
        )

        # Show error details
        errored_results = [r for r in report.results if r.error]
        if errored_results:
            # Deduplicate error messages
            unique_errors: dict[str, list[str]] = {}
            for r in errored_results:
                err = r.error or "Unknown error"
                err_short = err.split("\n")[0][:120]
                unique_errors.setdefault(err_short, []).append(r.check_id)

            console.print("\n[bold]Errors:[/bold]")
            for err_msg, check_ids in unique_errors.items():
                console.print(f"  [red]{err_msg}[/red]")
                console.print(f"  [dim]Affected checks: {', '.join(check_ids)}[/dim]\n")

        # Common fix suggestions
        console.print("[bold]Common fixes:[/bold]")
        console.print("  1. Check your GCP credentials: [cyan]gcloud auth application-default print-access-token[/cyan]")
        console.print("  2. Re-authenticate: [cyan]gcloud auth application-default login[/cyan]")
        console.print("  3. Verify project: [cyan]gcp-auditor scan --project my-project[/cyan]")
        console.print("  4. Use a service account: [cyan]gcp-auditor scan --service-account-key sa-key.json[/cyan]")
        return

    # Score panel
    score = s.score
    if score >= 80:
        score_color = "green"
    elif score >= 50:
        score_color = "yellow"
    else:
        score_color = "red"

    console.print()
    console.print(
        Panel(
            f"[bold {score_color}]{score}[/bold {score_color}] / 100",
            title="[bold]Health Score[/bold]",
            border_style=score_color,
            width=30,
        )
    )

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", report.provider.upper())
    table.add_row("Account", report.account_id or "unknown")
    table.add_row("Regions", ", ".join(report.regions) if report.regions else "default")
    table.add_row("Duration", f"{report.duration_seconds}s")
    table.add_row("Resources scanned", str(s.resources_scanned))
    table.add_row("Checks passed", f"[green]{s.checks_passed}[/green]")
    table.add_row("Checks failed", f"[red]{s.checks_failed}[/red]" if s.checks_failed else "0")
    if s.checks_errored:
        table.add_row("Checks errored", f"[yellow]{s.checks_errored}[/yellow]")
    if suppressed_count:
        table.add_row("Findings suppressed", f"[dim]{suppressed_count}[/dim]")
    console.print(table)

    # Show errors if any (partial failure)
    if s.checks_errored:
        errored_results = [r for r in report.results if r.error]
        console.print(f"\n[yellow]Warning: {s.checks_errored} check(s) failed with errors:[/yellow]")
        for r in errored_results:
            err_short = (r.error or "Unknown")[:100]
            console.print(f"  [dim]{r.check_name}:[/dim] [yellow]{err_short}[/yellow]")

    # Findings by severity
    if s.by_severity:
        console.print("\n[bold]Findings by severity:[/bold]")
        for sev in Severity:
            count = s.by_severity.get(sev, 0)
            if count:
                color = SEVERITY_COLORS[sev]
                icon = SEVERITY_ICONS[sev]
                console.print(f"  [{color}]{icon} {sev.value.upper()}: {count}[/{color}]")

    # Top findings
    findings = report.all_findings
    if findings:
        severity_order = list(Severity)
        findings_sorted = sorted(findings, key=lambda f: severity_order.index(f.severity))

        shown = min(len(findings_sorted), 10)
        console.print(f"\n[bold]Top findings ({shown} of {len(findings_sorted)}):[/bold]\n")

        findings_table = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
        findings_table.add_column("Sev", width=8)
        findings_table.add_column("Region", width=14)
        findings_table.add_column("Check")
        findings_table.add_column("Resource")
        findings_table.add_column("Title", max_width=60)

        for f in findings_sorted[:10]:
            sev_color = SEVERITY_COLORS[f.severity]
            findings_table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f"[dim]{f.region or 'global'}[/dim]",
                f.check_id,
                f.resource_id[:40],
                f.title[:60],
            )

        console.print(findings_table)

        if len(findings_sorted) > 10:
            remaining = len(findings_sorted) - 10
            console.print(f"\n  [dim]... and {remaining} more. See full report for details.[/dim]")
    elif not s.checks_errored:
        console.print("\n[bold green]No issues found. Your infrastructure looks great![/bold green]")


EFFORT_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
}


def _print_remediation(findings: list[Finding]) -> None:
    """Print remediation details for findings that have them."""
    actionable = [f for f in findings if f.remediation]
    if not actionable:
        return

    severity_order = list(Severity)
    actionable.sort(key=lambda f: severity_order.index(f.severity))

    console.print(f"\n[bold]Remediation details ({len(actionable)} actionable findings):[/bold]\n")

    for f in actionable:
        rem = f.remediation
        if rem is None:
            continue
        sev_color = SEVERITY_COLORS[f.severity]
        effort_color = EFFORT_COLORS[rem.effort.value]

        console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}")
        console.print(f"  [dim]Resource:[/dim] {f.resource_id}")
        if f.compliance_refs:
            console.print(f"  [dim]Compliance:[/dim] {', '.join(f.compliance_refs)}")
        console.print(f"  [dim]Effort:[/dim] [{effort_color}]{rem.effort.value.upper()}[/{effort_color}]")
        console.print(f"  [dim]gcloud:[/dim] [cyan]{rem.cli}[/cyan]")
        if rem.terraform:
            # Show first line of terraform snippet as preview
            tf_preview = rem.terraform.split("\n")[0]
            console.print(f"  [dim]Terraform:[/dim] {tf_preview} ...")
        console.print(f"  [dim]Docs:[/dim] {rem.doc_url}")
        console.print()


def _sanitize_shell(value: str) -> str:
    """Strip shell metacharacters from values embedded in bash script comments."""
    return re.sub(r"[`$();&|\\'\"\n\r]", "", value)


def _export_fixes(findings: list[Finding], output_path: Path) -> None:
    """Export CLI remediation commands as a bash script."""
    actionable = [f for f in findings if f.remediation]
    if not actionable:
        console.print("[yellow]No actionable findings - nothing to export.[/yellow]")
        return

    severity_order = list(Severity)
    actionable.sort(key=lambda f: severity_order.index(f.severity))

    lines = [
        "#!/bin/bash",
        "set -e",
        "",
        "# =============================================================================",
        "# gcp-auditor remediation script",
        "# Generated by gcp-auditor - https://github.com/abdullahkamil/gcp-auditor",
        "# =============================================================================",
        "#",
        "# DRY RUN: All commands are commented out by default.",
        "# Review each command carefully, then uncomment to execute.",
        "#",
        f"# Total actionable findings: {len(actionable)}",
        "# =============================================================================",
        "",
    ]

    for f in actionable:
        rem = f.remediation
        if rem is None:
            continue
        lines.append(f"# [{f.severity.value.upper()}] {_sanitize_shell(f.title)}")
        lines.append(f"# Resource: {_sanitize_shell(f.resource_id)}")
        if f.compliance_refs:
            lines.append(f"# Compliance: {', '.join(f.compliance_refs)}")
        lines.append(f"# {_sanitize_shell(rem.cli)}")
        lines.append("")

    import contextlib

    output_path.write_text("\n".join(lines), encoding="utf-8")
    with contextlib.suppress(OSError):
        output_path.chmod(0o700)
    console.print(f"\n[green]Remediation script saved to {output_path}[/green]")
    console.print(f"[dim]  {len(actionable)} commands (commented out). Review before uncommenting.[/dim]")


def _resolve_env_regions() -> str | None:
    """Read GCP_AUDITOR_REGIONS env var."""
    return os.environ.get("GCP_AUDITOR_REGIONS")


def _resolve_env_min_severity() -> Severity | None:
    """Read GCP_AUDITOR_MIN_SEVERITY env var."""
    val = os.environ.get("GCP_AUDITOR_MIN_SEVERITY")
    if val:
        try:
            return Severity(val.lower())
        except ValueError:
            console.print(
                f"[red]Invalid GCP_AUDITOR_MIN_SEVERITY='{val}'. Valid: {', '.join(s.value for s in Severity)}[/red]"
            )
            raise typer.Exit(2) from None
    return None


def _resolve_env_exclude_checks() -> list[str] | None:
    """Read GCP_AUDITOR_EXCLUDE_CHECKS env var."""
    val = os.environ.get("GCP_AUDITOR_EXCLUDE_CHECKS")
    if val:
        return [c.strip() for c in val.split(",") if c.strip()]
    return None


def _resolve_env_role_arn() -> str | None:
    """Read GCP_AUDITOR_SERVICE_ACCOUNT_KEY env var."""
    return os.environ.get("GCP_AUDITOR_SERVICE_ACCOUNT_KEY")


@app.command()
def scan(
    project: Annotated[str | None, typer.Option("--project", "-p", help="GCP project ID")] = None,
    service_account_key: Annotated[
        str | None, typer.Option("--service-account-key", help="Path to GCP service account key JSON file")
    ] = None,
    regions: Annotated[str | None, typer.Option("--regions", "-r", help="Comma-separated regions, or 'all'")] = None,
    categories: Annotated[
        str | None, typer.Option("--categories", "-c", help="Filter: security,cost,reliability")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
    fmt: Annotated[
        str | None, typer.Option("--format", "-f", help="Output format: json, html, sarif, markdown")
    ] = None,
    min_severity: Annotated[
        str | None, typer.Option("--min-severity", help="Minimum severity: critical, high, medium, low, info")
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Quiet mode - exit code only")] = False,
    config: Annotated[Path | None, typer.Option("--config", help="Path to .gcp-auditor.yml config file")] = None,
    remediation: Annotated[
        bool, typer.Option("--remediation", "-R", help="Show remediation details for findings")
    ] = False,
    export_fixes: Annotated[
        Path | None, typer.Option("--export-fixes", help="Export gcloud fix commands as bash script")
    ] = None,
) -> None:
    """Scan GCP infrastructure and generate an audit report with ISO 27001 and SOC 2 mappings."""
    from cloud_audit.config import CloudAuditConfig, load_config
    from cloud_audit.scanner import run_scan

    # Load config file
    try:
        cfg = load_config(config)
    except Exception as e:
        console.print(f"[red]Config error: {e}[/red]")
        raise typer.Exit(2) from None

    # Resolve precedence: CLI flags > env vars > config > defaults

    # Regions: CLI > env > config
    env_regions = _resolve_env_regions()
    if regions:
        region_list = [r.strip() for r in regions.split(",")]
    elif env_regions:
        region_list = [r.strip() for r in env_regions.split(",")]
    elif cfg.regions:
        region_list = cfg.regions
    else:
        region_list = None

    # Service account key: CLI > env > config
    effective_sa_key = service_account_key or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or cfg.service_account_key

    # Min severity: CLI > env > config
    env_severity = _resolve_env_min_severity()
    effective_severity: Severity | None = None
    if min_severity:
        try:
            effective_severity = Severity(min_severity.lower())
        except ValueError:
            console.print(
                f"[red]Invalid --min-severity='{min_severity}'. Valid: {', '.join(s.value for s in Severity)}[/red]"
            )
            raise typer.Exit(2) from None
    elif env_severity:
        effective_severity = env_severity
    elif cfg.min_severity:
        effective_severity = cfg.min_severity

    # Exclude checks: env extends config
    env_excludes = _resolve_env_exclude_checks()
    all_excludes = list(set(cfg.exclude_checks + env_excludes)) if env_excludes else cfg.exclude_checks

    # Build effective config for scanner
    effective_config = CloudAuditConfig(
        provider="gcp",
        project=project or cfg.project,
        service_account_key=effective_sa_key,
        regions=region_list,
        min_severity=effective_severity,
        exclude_checks=all_excludes,
        suppressions=cfg.suppressions,
    )

    # Validate format early (before scan) to avoid wasting time
    if fmt and fmt not in ("json", "html", "sarif", "markdown"):
        console.print(f"[red]Unknown format '{fmt}'. Available: json, html, sarif, markdown[/red]")
        raise typer.Exit(2)
    if fmt == "html" and not output:
        console.print("[red]HTML format requires --output <file.html>[/red]")
        raise typer.Exit(2)

    category_list = [c.strip().lower() for c in categories.split(",")] if categories else None

    # Initialize GCP provider
    from cloud_audit.providers.gcp import GCPProvider

    try:
        effective_project = project or cfg.project
        cloud_provider = GCPProvider(
            project=effective_project,
            regions=region_list,
            service_account_key=effective_sa_key,
        )
    except Exception as e:
        console.print(f"[red]GCP authentication failed: {e}[/red]")
        console.print("\n[bold]Common fixes:[/bold]")
        console.print("  1. Authenticate: [cyan]gcloud auth application-default login[/cyan]")
        console.print("  2. Set project: [cyan]gcp-auditor scan --project my-project-id[/cyan]")
        console.print("  3. Use service account: [cyan]gcp-auditor scan --service-account-key sa.json[/cyan]")
        raise typer.Exit(2) from None

    # Run scan
    report, suppressed_count = run_scan(
        cloud_provider,
        categories=category_list,
        config=effective_config,
        quiet=quiet,
    )

    # Determine exit code: 0=clean, 1=findings, 2=errors
    has_findings = report.summary.total_findings > 0
    s = report.summary
    all_errored = s.checks_errored > 0 and s.checks_passed == 0 and s.checks_failed == 0

    # Format output
    if fmt:
        _handle_format(fmt, report, output, quiet)
    elif output:
        # Backward compat: detect format from suffix
        suffix = output.suffix.lower()
        suffix_to_fmt = {".json": "json", ".html": "html", ".sarif": "sarif", ".md": "markdown"}
        detected_fmt = suffix_to_fmt.get(suffix)
        if detected_fmt:
            _handle_format(detected_fmt, report, output, quiet)
        else:
            console.print(f"[red]Cannot detect format from suffix '{suffix}'. Use --format explicitly.[/red]")
            raise typer.Exit(2)
    else:
        # Default: Rich console output
        if not quiet:
            _print_summary(report, suppressed_count)

            if remediation:
                _print_remediation(report.all_findings)

            if export_fixes:
                _export_fixes(report.all_findings, export_fixes)

    # Exit code
    if all_errored:
        raise typer.Exit(2)
    if has_findings:
        raise typer.Exit(1)


def _handle_format(fmt: str, report: ScanReport, output: Path | None, quiet: bool) -> None:
    """Handle --format output. Writes to file or stdout."""
    if fmt == "json":
        content = report.model_dump_json(indent=2)
    elif fmt == "sarif":
        from cloud_audit.reports.sarif import generate_sarif

        content = generate_sarif(report)
    elif fmt == "markdown":
        from cloud_audit.reports.markdown import generate_markdown

        content = generate_markdown(report)
    elif fmt == "html":
        if not output:
            console.print("[red]HTML format requires --output <file.html>[/red]")
            raise typer.Exit(2)
        from cloud_audit.reports.html import render_html

        content = render_html(report)
    else:
        console.print(f"[red]Unknown format '{fmt}'. Available: json, html, sarif, markdown[/red]")
        raise typer.Exit(2)

    if output:
        output.write_text(content, encoding="utf-8")
        if not quiet:
            console.print(f"[green]{fmt.upper()} report saved to {output}[/green]")
    else:
        sys.stdout.write(content)
        sys.stdout.write("\n")


@app.command(name="list-checks")
def list_checks(
    categories: Annotated[
        str | None, typer.Option("--categories", "-c", help="Filter: security,cost,reliability")
    ] = None,
) -> None:
    """List all available GCP checks."""
    from cloud_audit.providers.gcp.provider import _CHECK_MODULES

    category_list = [c.strip().lower() for c in categories.split(",")] if categories else None

    table = Table(title="Available checks (GCP)", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Category")
    table.add_column("Service")
    table.add_column("Compliance")

    count = 0
    for module in _CHECK_MODULES:
        # Module name = service name (e.g., iam, storage, compute)
        service = module.__name__.rsplit(".", 1)[-1].rstrip("_")

        _sentinel = type("_Sentinel", (), {})()
        try:
            checks = module.get_checks(_sentinel)
        except Exception as exc:  # noqa: S112
            console.print(f"[yellow]Warning: failed to load checks from {module.__name__}: {exc}[/yellow]")
            continue

        for check_fn in checks:
            category = getattr(check_fn, "category", "unknown")

            cat_val = getattr(category, "value", str(category))
            if category_list and cat_val not in category_list:
                continue

            func_name = getattr(check_fn, "func", check_fn).__name__
            readable = func_name.replace("check_", "").replace("_", " ").title()
            check_id = getattr(check_fn, "check_id", "")

            cat_color = {"security": "red", "cost": "yellow", "reliability": "cyan", "performance": "green"}.get(
                str(getattr(category, "value", category)), "white"
            )

            table.add_row(
                f"{check_id} {readable}",
                f"[{cat_color}]{getattr(category, 'value', category).upper()}[/{cat_color}]",
                service.upper(),
                "[dim]ISO 27001, SOC 2[/dim]",
            )
            count += 1

    console.print(table)
    console.print(f"\n[dim]Total: {count} checks[/dim]")


@app.command()
def demo() -> None:
    """Show a demo scan with sample output (no GCP credentials needed)."""
    import time

    from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

    console.print()

    # Simulate progress bar
    with Progress(
        TextColumn("[bold]Running 30 checks on GCP..."),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning", total=30)
        for _ in range(30):
            time.sleep(0.08)
            progress.advance(task)

    # Health score
    console.print()
    console.print(
        Panel(
            "[bold yellow]58[/bold yellow] / 100",
            title="[bold]Health Score[/bold]",
            border_style="yellow",
            width=30,
        )
    )

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", "GCP")
    table.add_row("Project", "my-project-123456")
    table.add_row("Regions", "us-central1")
    table.add_row("Duration", "18s")
    table.add_row("Resources scanned", "112")
    table.add_row("Checks passed", "[green]14[/green]")
    table.add_row("Checks failed", "[red]8[/red]")
    console.print(table)

    # Findings by severity
    console.print("\n[bold]Findings by severity:[/bold]")
    console.print("  [bold red]x CRITICAL: 3[/bold red]")
    console.print("  [red]x HIGH: 5[/red]")
    console.print("  [yellow]! MEDIUM: 6[/yellow]")
    console.print("  [cyan]o LOW: 2[/cyan]")

    # Top findings
    console.print("\n[bold]Top findings (5 of 16):[/bold]\n")

    ft = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
    ft.add_column("Sev", width=8)
    ft.add_column("Region", width=14)
    ft.add_column("Check")
    ft.add_column("Resource")
    ft.add_column("Title", max_width=55)
    ft.add_row(
        "[bold red]CRITICAL[/bold red]",
        "[dim]global[/dim]",
        "gcp-storage-001",
        "gs://public-data-bucket",
        "Cloud Storage bucket publicly accessible",
    )
    ft.add_row(
        "[bold red]CRITICAL[/bold red]",
        "[dim]global[/dim]",
        "gcp-firewall-001",
        "default-allow-ssh",
        "Firewall rule allows 0.0.0.0/0 on port 22",
    )
    ft.add_row(
        "[bold red]CRITICAL[/bold red]",
        "[dim]us-central1[/dim]",
        "gcp-sql-001",
        "production-db",
        "Cloud SQL instance has public IP",
    )
    ft.add_row(
        "[red]HIGH[/red]",
        "[dim]global[/dim]",
        "gcp-iam-001",
        "deploy-sa@my-project.iam",
        "Service account key older than 90 days",
    )
    ft.add_row(
        "[yellow]MEDIUM[/yellow]",
        "[dim]global[/dim]",
        "gcp-compute-004",
        "web-server-01",
        "OS Login not enabled on instance",
    )
    console.print(ft)

    console.print("\n  [dim]... and 11 more. See full report for details.[/dim]")

    # Remediation preview
    console.print("\n[bold]Remediation details (2 of 8 actionable findings):[/bold]\n")

    console.print("  [bold red]CRITICAL[/bold red]  Cloud Storage bucket publicly accessible")
    console.print("  [dim]Resource:[/dim]   gs://public-data-bucket")
    console.print("  [dim]Compliance:[/dim] ISO 27001 A.8.3, SOC 2 CC6.1, CIS GCP 5.1")
    console.print("  [dim]Effort:[/dim]     [green]LOW[/green]")
    bucket_cli = "gcloud storage buckets update gs://public-data-bucket --no-public-access-prevention"
    console.print(f"  [dim]gcloud:[/dim]     [cyan]{bucket_cli}[/cyan]")
    console.print('  [dim]Terraform:[/dim]  resource "google_storage_bucket_iam_member" { ... }')
    bucket_docs = "https://cloud.google.com/storage/docs/using-public-access-prevention"
    console.print(f"  [dim]Docs:[/dim]       {bucket_docs}")
    console.print()

    console.print("  [bold red]CRITICAL[/bold red]  Firewall rule allows 0.0.0.0/0 on port 22")
    console.print("  [dim]Resource:[/dim]   default-allow-ssh")
    console.print("  [dim]Compliance:[/dim] ISO 27001 A.13.1, SOC 2 CC6.6, CIS GCP 3.6")
    console.print("  [dim]Effort:[/dim]     [green]LOW[/green]")
    fw_cli = "gcloud compute firewall-rules update default-allow-ssh --source-ranges=10.0.0.0/8"
    console.print(f"  [dim]gcloud:[/dim]     [cyan]{fw_cli}[/cyan]")
    console.print('  [dim]Terraform:[/dim]  resource "google_compute_firewall" "ssh" { ... }')
    fw_docs = "https://cloud.google.com/vpc/docs/firewalls"
    console.print(f"  [dim]Docs:[/dim]       {fw_docs}")
    console.print()

    console.print(
        "[dim]This is sample output. Run [bold]gcp-auditor scan[/bold] with GCP credentials for a real scan.[/dim]"
    )


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"gcp-auditor {__version__}")


if __name__ == "__main__":
    app()
