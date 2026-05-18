"""Typer CLI for Vastcat."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional
import os
import shlex
import shutil

import typer
from rich.console import Console

from .assets import ASSET_LIBRARY, AssetManager, list_assets
from .config import ensure_config
from .deployment import render_hashcat_command, render_startup_script
from .hashcat import HashcatRunner
from .notifier import Notifier
from .theme import cat_say
from .wizard import Wizard

app = typer.Typer(help="Cat-themed hashcat orchestrator")
assets_app = typer.Typer(help="Manage wordlists and rules")
vast_app   = typer.Typer(help="Manage Vast.ai instances")
app.add_typer(assets_app, name="assets")
app.add_typer(vast_app,   name="vast")


def check_hashcat_with_warning(console: Console, auto_install: bool = False) -> bool:
    """Check if hashcat is installed and warn if not.

    Returns True if hashcat is available. When auto_install=True will attempt
    installation without prompting (used by the `run` command); otherwise just
    warns and lets the wizard continue so the user can still generate scripts.
    """
    from .install_hashcat import check_hashcat_installed, download_and_install_hashcat

    if check_hashcat_installed():
        return True

    console.print("\n[bold yellow]⚠️  Hashcat not found.[/bold yellow]")

    if auto_install:
        console.print("[dim]Attempting installation...[/dim]\n")
        try:
            success = download_and_install_hashcat(verbose=True)
            if success and check_hashcat_installed():
                console.print("[green]✓ Hashcat installed.[/green]\n")
                return True
        except Exception as exc:
            console.print(f"[yellow]Installation failed: {exc}[/yellow]")

    console.print("[dim]Install hashcat to run jobs locally:[/dim]")
    console.print("  [cyan]vastcat install-hashcat[/cyan]  — platform instructions")
    console.print("  [dim]Ubuntu/Debian: sudo apt install hashcat[/dim]")
    console.print("  [dim]macOS:         brew install hashcat[/dim]\n")
    return False


@assets_app.command("list")
def assets_list(category: Optional[str] = typer.Option(None, "--category", "-c")) -> None:
    console = Console()
    manager = AssetManager()
    names = list_assets(category)
    if not names:
        console.print("No assets found.")
        return
    for key in names:
        asset = ASSET_LIBRARY[key]
        console.print(f"[bold]{key}[/bold]: {asset.description or asset.name} -> {manager.resolved_paths([key])[0]}")


@assets_app.command("sync")
def assets_sync(
    names: List[str] = typer.Argument(None),
    force: bool = typer.Option(False, "--force", help="Re-download assets"),
) -> None:
    manager = AssetManager()
    targets = names or None
    paths = manager.sync(targets, force=force)
    console = Console()
    for path in paths:
        console.print(cat_say(f"Ready: {path}"))


@app.command()
def run(
    hash_file: Path = typer.Argument(..., help="File containing hashes"),
    hash_mode: str = typer.Option("0", "--mode", "-m"),
    attack_mode: str = typer.Option("0", "--attack", "-a"),
    wordlists: List[Path] = typer.Option(..., "--wordlist", "-w"),
    rules: List[Path] = typer.Option([], "--rule", "-r"),
    extra: str = typer.Option("--status --status-timer=60", help="Additional hashcat flags"),
    dry_run: bool = typer.Option(False, help="Only print the command"),
) -> None:
    """Run hashcat with manual parameters."""
    console = Console()
    if not check_hashcat_with_warning(console, auto_install=True):
        raise typer.Exit(1)

    command = render_hashcat_command(
        hash_path=str(hash_file),
        hash_mode=hash_mode,
        attack_mode=attack_mode,
        wordlists=[str(path) for path in wordlists],
        rules=[str(path) for path in rules],
        extra_args=extra,
    )
    runner = HashcatRunner(notifier=Notifier(ensure_config().get("discord_webhook")))
    runner.run(shlex.split(command)[1:], dry_run=dry_run)


@app.command()
def wizard() -> None:
    """Start the interactive configuration wizard."""
    console = Console()
    check_hashcat_with_warning(console, auto_install=False)
    Wizard(console).run()


@app.command(name="doctor")
def doctor() -> None:
    """Check vastcat setup and dependencies."""
    console = Console()
    console.print("\n[bold cyan]VastCat Setup Check[/bold cyan]\n")

    # Check hashcat - try local installation first
    local_hashcat = Path.home() / ".local" / "share" / "vastcat" / "hashcat" / "hashcat"
    local_bin = Path.home() / ".local" / "bin" / "hashcat"
    system_hashcat = shutil.which("hashcat")

    hashcat_found = False
    hashcat_path = None

    if local_hashcat.exists() and os.access(local_hashcat, os.X_OK):
        hashcat_path = str(local_hashcat)
        hashcat_found = True
        console.print(f"[green]✓[/green] Hashcat (local): [dim]{hashcat_path}[/dim]")
    elif local_bin.exists() and os.access(local_bin, os.X_OK):
        hashcat_path = str(local_bin)
        hashcat_found = True
        console.print(f"[green]✓[/green] Hashcat (local): [dim]{hashcat_path}[/dim]")
    elif system_hashcat:
        hashcat_path = system_hashcat
        hashcat_found = True
        console.print(f"[green]✓[/green] Hashcat (system): [dim]{hashcat_path}[/dim]")
    else:
        console.print("[red]✗[/red] Hashcat not found")
        console.print("  [dim]Try reinstalling: pip install --force-reinstall vastcat[/dim]")
        console.print("  [dim]Or run: vastcat install-hashcat[/dim]")

    if hashcat_found and hashcat_path:
        # Try to get version
        import subprocess
        try:
            result = subprocess.run([hashcat_path, "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                console.print(f"  [dim]Version: {version}[/dim]")
        except Exception:
            pass

    # Check name-that-hash
    try:
        from vastcat.detect import NTH_AVAILABLE
        if NTH_AVAILABLE:
            import name_that_hash
            console.print(f"[green]✓[/green] name-that-hash available: [dim]v{name_that_hash.__version__}[/dim]")
        else:
            console.print("[yellow]⚠[/yellow] name-that-hash not available (using regex fallback)")
    except Exception as e:
        console.print(f"[red]✗[/red] Error checking name-that-hash: {e}")

    # Check config
    try:
        config = ensure_config()
        config_file = Path.home() / ".config" / "vastcat" / "config.yaml"
        console.print(f"[green]✓[/green] Config file: [dim]{config_file}[/dim]")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Config issue: {e}")

    # Check cache directory
    cache_dir = Path.home() / ".cache" / "vastcat"
    if cache_dir.exists():
        console.print(f"[green]✓[/green] Cache directory: [dim]{cache_dir}[/dim]")
    else:
        console.print(f"[dim]  Cache directory will be created on first use[/dim]")

    console.print("\n[bold]Status:[/bold]")
    if hashcat_path:
        console.print("  [green]Ready to crack![/green] Run [cyan]vastcat wizard[/cyan] to get started.\n")
    else:
        console.print("  [yellow]Install hashcat to begin.[/yellow] Run [cyan]vastcat install-hashcat[/cyan] for instructions.\n")


@vast_app.command("list")
def vast_list() -> None:
    """List your running Vast.ai instances."""
    console = Console()
    config = ensure_config()
    api_key = config.get("vast_api_key") or os.environ.get("VAST_API_KEY", "")
    if not api_key:
        console.print("[red]No Vast.ai API key configured. Run vastcat wizard or set VAST_API_KEY.[/red]")
        raise typer.Exit(1)
    from .vast import VastClient, VastError
    try:
        client = VastClient(api_key)
        instances = client.list_instances()
    except VastError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    if not instances:
        console.print(cat_say("No active instances."))
        return
    for inst in instances:
        console.print(
            f"[bold]{inst.id}[/bold]  {inst.status:10}  {inst.num_gpus}x {inst.gpu_name}"
            f"  ${inst.hourly:.3f}/hr  ssh -p {inst.ssh_port} root@{inst.ssh_host}"
            + (f"  [{inst.label}]" if inst.label else "")
        )


@vast_app.command("destroy")
def vast_destroy(instance_id: int = typer.Argument(..., help="Instance ID to destroy")) -> None:
    """Destroy a Vast.ai instance."""
    console = Console()
    config = ensure_config()
    api_key = config.get("vast_api_key") or os.environ.get("VAST_API_KEY", "")
    if not api_key:
        console.print("[red]No Vast.ai API key configured.[/red]")
        raise typer.Exit(1)
    from .vast import VastClient, VastError
    import questionary
    if not questionary.confirm(f"Destroy instance {instance_id}?", default=False).ask():
        console.print("Cancelled.")
        return
    try:
        VastClient(api_key).destroy_instance(instance_id)
        console.print(cat_say(f"Instance {instance_id} destroyed."))
    except VastError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


@vast_app.command("search")
def vast_search(
    max_price: float = typer.Option(0.50, help="Max $/hr"),
    min_vram: float  = typer.Option(8.0,  help="Min VRAM GB"),
) -> None:
    """Search for available Vast.ai GPU offers."""
    console = Console()
    config = ensure_config()
    api_key = config.get("vast_api_key") or os.environ.get("VAST_API_KEY", "")
    if not api_key:
        console.print("[red]No Vast.ai API key configured.[/red]")
        raise typer.Exit(1)
    from .vast import VastClient, VastError
    try:
        offers = VastClient(api_key).search_offers(
            min_vram_gb=min_vram, max_hourly=max_price
        )
    except VastError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    if not offers:
        console.print(cat_say("No offers found. Try raising --max-price or lowering --min-vram."))
        return
    for o in offers:
        console.print(o.display())


@app.command(name="install-hashcat")
def install_hashcat() -> None:
    """Display instructions for installing hashcat."""
    console = Console()
    console.print("\n[bold cyan]Hashcat Installation Instructions[/bold cyan]\n")

    console.print("[bold]Option 1: Package Manager (Recommended)[/bold]")
    console.print("  Ubuntu/Debian: [cyan]sudo apt update && sudo apt install -y hashcat[/cyan]")
    console.print("  Fedora/RHEL:   [cyan]sudo dnf install -y hashcat[/cyan]")
    console.print("  Arch Linux:    [cyan]sudo pacman -S hashcat[/cyan]")
    console.print("  macOS:         [cyan]brew install hashcat[/cyan]")

    console.print("\n[bold]Option 2: From Source (Latest Version)[/bold]")
    console.print("  1. Download:  [cyan]wget https://hashcat.net/files/hashcat-7.1.2.tar.gz[/cyan]")
    console.print("  2. Extract:   [cyan]tar -xzf hashcat-7.1.2.tar.gz[/cyan]")
    console.print("  3. Build:     [cyan]cd hashcat-7.1.2 && make[/cyan]")
    console.print("  4. Install:   [cyan]sudo make install[/cyan]")
    console.print("  Or symlink:   [cyan]sudo ln -s $(pwd)/hashcat /usr/local/bin/hashcat[/cyan]")

    console.print("\n[bold]Verify Installation:[/bold]")
    console.print("  [cyan]hashcat --version[/cyan]")
    console.print("  [cyan]vastcat doctor[/cyan]")

    console.print("\n[dim]After installation, run 'vastcat wizard' to start cracking![/dim]\n")
