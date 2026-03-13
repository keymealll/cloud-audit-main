"""Generate animated demo GIF for README using Rich console export + Pillow."""

import io
import textwrap

from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# We'll render multiple frames as SVG, convert to PNG via cairosvg, then combine into GIF
import cairosvg


TARGET_LINES = 52  # Fixed terminal height in lines


def pad_to_height(console, current_lines: int):
    """Add blank lines so every frame has the same terminal height."""
    for _ in range(max(0, TARGET_LINES - current_lines)):
        console.print()


def render_frame(lines_to_show: int, progress: int = 0) -> bytes:
    """Render a frame as PNG bytes."""
    buf = io.StringIO()
    console = Console(record=True, width=90, force_terminal=True, file=buf)

    # Frame 1: just the command
    console.print()
    console.print("[bold]$[/bold] cloud-audit scan --provider aws -R --output report.html")

    if lines_to_show < 1:
        pad_to_height(console, 3)
        svg = console.export_svg(title="cloud-audit")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 2+: progress bar
    console.print()
    console.print("[bold]Running 17 checks on AWS...[/bold]")
    bar_len = min(progress, 40)
    bar = "\u2501" * bar_len + " " * (40 - bar_len)
    done = int(progress * 17 / 40)
    console.print(f"[green]{bar}[/green] {done}/17")

    if lines_to_show < 2:
        pad_to_height(console, 6)
        svg = console.export_svg(title="cloud-audit")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 3+: health score + summary
    console.print()
    console.print(
        Panel(
            "[bold yellow]62[/bold yellow] / 100",
            title="[bold]Health Score[/bold]",
            border_style="yellow",
            width=30,
        )
    )

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", "AWS")
    table.add_row("Account", "123456789012")
    table.add_row("Regions", "eu-central-1")
    table.add_row("Duration", "12s")
    table.add_row("Resources scanned", "147")
    table.add_row("Checks passed", "[green]11[/green]")
    table.add_row("Checks failed", "[red]6[/red]")
    console.print(table)

    if lines_to_show < 3:
        pad_to_height(console, 16)
        svg = console.export_svg(title="cloud-audit")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 4+: severity
    console.print("\n[bold]Findings by severity:[/bold]")
    console.print("  [bold red]\u2716 CRITICAL: 2[/bold red]")
    console.print("  [red]\u2716 HIGH: 4[/red]")
    console.print("  [yellow]\u26a0 MEDIUM: 7[/yellow]")
    console.print("  [cyan]\u25cb LOW: 3[/cyan]")

    if lines_to_show < 4:
        pad_to_height(console, 22)
        svg = console.export_svg(title="cloud-audit")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 5+: findings table
    console.print("\n[bold]Top findings (5 of 16):[/bold]\n")

    ft = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
    ft.add_column("Sev", width=8)
    ft.add_column("Check", width=12)
    ft.add_column("Resource", width=28)
    ft.add_column("Title", max_width=35)
    ft.add_row(
        "[bold red]CRITICAL[/bold red]", "aws-iam-001",
        "arn:aws:iam::1234...:root", "Root account without MFA",
    )
    ft.add_row(
        "[bold red]CRITICAL[/bold red]", "aws-vpc-002",
        "sg-0a1b2c3d4e5f67890", "SG open to 0.0.0.0/0 on port 22",
    )
    ft.add_row(
        "[red]HIGH[/red]", "aws-rds-001",
        "production-db", "RDS publicly accessible",
    )
    ft.add_row(
        "[red]HIGH[/red]", "aws-s3-001",
        "company-backups-2024", "S3 public access block disabled",
    )
    ft.add_row(
        "[yellow]MEDIUM[/yellow]", "aws-iam-003",
        "deploy-key-AKIA...", "Access key 347 days old",
    )
    console.print(ft)

    if lines_to_show < 5:
        pad_to_height(console, 30)
        svg = console.export_svg(title="cloud-audit")
        return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)

    # Frame 6+: remediation
    console.print("\n[bold]Remediation (2 of 6 actionable):[/bold]\n")

    console.print("  [bold red]CRITICAL[/bold red]  Root account without MFA")
    console.print("  [dim]Compliance:[/dim] CIS 1.5  [dim]Effort:[/dim] [green]LOW[/green]")
    console.print(
        "  [dim]CLI:[/dim]  [cyan]aws iam create-virtual-mfa-device"
        " --virtual-mfa-device-name root-mfa[/cyan]"
    )
    console.print(
        '  [dim]Terraform:[/dim]  resource "aws_iam_virtual_mfa_device"'
        ' "root" { ... }'
    )
    console.print()
    console.print("  [bold red]CRITICAL[/bold red]  SG open to 0.0.0.0/0 on port 22")
    console.print("  [dim]Compliance:[/dim] CIS 5.2  [dim]Effort:[/dim] [green]LOW[/green]")
    console.print(
        "  [dim]CLI:[/dim]  [cyan]aws ec2 revoke-security-group-ingress"
        " --group-id sg-... --port 22[/cyan]"
    )
    console.print(
        '  [dim]Terraform:[/dim]  resource "aws_security_group_rule"'
        ' "ssh" { ... }'
    )
    console.print()
    console.print("[green]HTML report saved to report.html[/green]")

    pad_to_height(console, 48)
    svg = console.export_svg(title="cloud-audit")
    return cairosvg.svg2png(bytestring=svg.encode(), scale=1.5)


def main():
    frames = []

    # Frame 0: command typed (hold 1s = 2 frames at 500ms)
    png_data = render_frame(0)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frames 1-8: progress bar animation (fast)
    for p in range(0, 41, 5):
        png_data = render_frame(1, progress=p)
        img = Image.open(io.BytesIO(png_data))
        frames.append(img.copy())

    # Frame: health score + summary (hold 1.5s)
    png_data = render_frame(2)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: severity (hold 1s)
    png_data = render_frame(3)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: findings table (hold 2s)
    png_data = render_frame(4)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Frame: findings table done (hold 1s)
    png_data = render_frame(5)
    img = Image.open(io.BytesIO(png_data))
    frames.append(img.copy())

    # Final frame: full output with remediation (hold 4s)
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

    # Ensure all frames same size (pad to largest)
    max_w = max(f.width for f in frames)
    max_h = max(f.height for f in frames)

    padded_frames = []
    for f in frames:
        if f.width < max_w or f.height < max_h:
            # Create dark background and paste frame
            bg = Image.new("RGBA", (max_w, max_h), (40, 42, 54, 255))
            bg.paste(f, (0, 0))
            padded_frames.append(bg.convert("RGB"))
        else:
            padded_frames.append(f.convert("RGB"))

    # Save as animated GIF
    padded_frames[0].save(
        "assets/demo.gif",
        save_all=True,
        append_images=padded_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )

    import os
    size = os.path.getsize("assets/demo.gif")
    print(f"GIF saved to assets/demo.gif ({size / 1024:.0f} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
