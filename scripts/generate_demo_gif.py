"""Generate animated demo GIF for README using Rich console export + Pillow."""

import io
import os

from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import cairosvg


TARGET_LINES = 52


def pad_to_height(console, current_lines: int):
    """Add blank lines so every frame has the same terminal height."""
    for _ in range(max(0, TARGET_LINES - current_lines)):
        console.print()


def render_frame(lines_to_show: int, progress: int = 0) -> bytes:
    """Render a frame as PNG bytes."""
    buf = io.StringIO()
    console = Console(record=True, width=90, force_terminal=True, file=buf)

    # Frame 0: just the command
    console.print()
    console.print("[bold]$[/bold] gcp-auditor scan -R")

    if lines_to_show < 1:
        pad_to_height(console, 3)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 1+: progress bar
    console.print()
    console.print("[bold]Running 30 checks on GCP...[/bold]")
    bar_len = min(progress, 40)
    bar = "\u2501" * bar_len + " " * (40 - bar_len)
    done = int(progress * 30 / 40)
    console.print(f"[green]{bar}[/green] {done}/30")

    if lines_to_show < 2:
        pad_to_height(console, 6)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 2+: health score + summary
    console.print()
    console.print(
        Panel(
            "[bold yellow]58[/bold yellow] / 100",
            title="[bold]Health Score[/bold]",
            border_style="yellow",
            width=30,
        )
    )

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", "GCP")
    table.add_row("Project", "my-project-123456")
    table.add_row("Regions", "us-central1")
    table.add_row("Resources scanned", "112")
    table.add_row("Checks passed", "[green]14[/green]")
    table.add_row("Checks failed", "[red]8[/red]")
    console.print(table)

    if lines_to_show < 3:
        pad_to_height(console, 15)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 3+: severity
    console.print("\n[bold]Findings by severity:[/bold]")
    console.print("  [bold red]\u2716 CRITICAL: 3[/bold red]")
    console.print("  [red]\u2716 HIGH: 5[/red]")
    console.print("  [yellow]\u26a0 MEDIUM: 6[/yellow]")
    console.print("  [cyan]\u25cb LOW: 2[/cyan]")

    if lines_to_show < 4:
        pad_to_height(console, 22)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 4+: findings table
    console.print("\n[bold]Top findings (5 of 16):[/bold]\n")

    ft = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
    ft.add_column("Sev", width=8)
    ft.add_column("Check", width=14)
    ft.add_column("Resource", width=28)
    ft.add_column("Title", max_width=35)
    ft.add_row(
        "[bold red]CRITICAL[/bold red]", "gcp-storage-001",
        "gs://public-data-bucket", "Bucket publicly accessible",
    )
    ft.add_row(
        "[bold red]CRITICAL[/bold red]", "gcp-firewall-001",
        "default-allow-ssh", "Firewall open to 0.0.0.0/0 on port 22",
    )
    ft.add_row(
        "[red]HIGH[/red]", "gcp-sql-001",
        "production-db", "Cloud SQL publicly accessible",
    )
    ft.add_row(
        "[red]HIGH[/red]", "gcp-iam-001",
        "deploy-sa@project.iam", "Service account key 120 days old",
    )
    ft.add_row(
        "[yellow]MEDIUM[/yellow]", "gcp-compute-004",
        "web-server-01", "OS Login not enabled",
    )
    console.print(ft)

    if lines_to_show < 5:
        pad_to_height(console, 30)
        svg = console.export_svg(title="gcp-auditor")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 5+: remediation
    console.print("\n[bold]Remediation (2 of 6 actionable):[/bold]\n")

    console.print("  [bold red]CRITICAL[/bold red]  Cloud Storage bucket publicly accessible")
    console.print("  [dim]Compliance:[/dim] ISO 27001 A.8.3, SOC 2 CC6.1  [dim]Effort:[/dim] [green]LOW[/green]")
    console.print(
        "  [dim]CLI:[/dim]  [cyan]gcloud storage buckets update gs://public-data-bucket"
        " --public-access-prevention=enforced[/cyan]"
    )
    console.print(
        '  [dim]Terraform:[/dim]  resource "google_storage_bucket" '
        '"bucket" { ... }'
    )
    console.print()
    console.print("  [bold red]CRITICAL[/bold red]  Firewall rule allows 0.0.0.0/0 on port 22")
    console.print("  [dim]Compliance:[/dim] ISO 27001 A.13.1, CIS GCP 3.6  [dim]Effort:[/dim] [green]LOW[/green]")
    console.print(
        "  [dim]CLI:[/dim]  [cyan]gcloud compute firewall-rules update default-allow-ssh"
        " --source-ranges=10.0.0.0/8[/cyan]"
    )
    console.print(
        '  [dim]Terraform:[/dim]  resource "google_compute_firewall" '
        '"ssh" { ... }'
    )
    console.print()
    console.print("[green]HTML report saved to report.html[/green]")

    pad_to_height(console, 48)
    svg = console.export_svg(title="gcp-auditor")
    return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)


def main():
    frames = []

    # Frame 0: command typed
    png_data = render_frame(0)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frames 1-8: progress bar animation
    for p in range(0, 41, 5):
        png_data = render_frame(1, progress=p)
        img = Image.open(io.BytesIO(png_data))
        frames.append(img.copy())

    # Frame: health score + summary
    png_data = render_frame(2)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: severity
    png_data = render_frame(3)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: findings table
    png_data = render_frame(4)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: findings table done
    png_data = render_frame(5)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Final frame: full output with remediation
    png_data = render_frame(6)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Durations in ms per frame
    durations = (
        [800]           # command
        + [120] * 9     # progress bar (9 steps)
        + [1500]        # health score
        + [1000]        # severity
        + [1500]        # findings table appearing
        + [1000]        # findings done
        + [5000]        # final with remediation (long hold)
    )

    # Ensure all frames same size
    max_w = max(f.width for f in frames)
    max_h = max(f.height for f in frames)

    padded_frames = []
    for f in frames:
        if f.width < max_w or f.height < max_h:
            bg = Image.new("RGBA", (max_w, max_h), (40, 42, 54, 255))
            bg.paste(f, (0, 0))
            padded_frames.append(bg.convert("RGB"))
        else:
            padded_frames.append(f.convert("RGB"))

    padded_frames[0].save(
        "assets/demo.gif",
        save_all=True,
        append_images=padded_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )

    size = os.path.getsize("assets/demo.gif")
    print(f"GIF saved to assets/demo.gif ({size / 1024:.0f} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
