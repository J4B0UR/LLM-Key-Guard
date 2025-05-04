"""Command-line interface for LLM Key Guard."""

import os
import sys
import json
import time
import glob
import tempfile
import subprocess
import importlib.util
from pathlib import Path
from typing import List, Optional, Tuple, Union

import typer
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich import print as rich_print

from llm_key_guard import __version__
from llm_key_guard.detectors import Confidence, KeyFinding, Provider
from llm_key_guard.scanner import SlackScanner, scan_directory, scan_github_actions, scan_git_history, scan_git_branch_comparison
from llm_key_guard.validator import KeyValidator
from llm_key_guard.revoker import create_env_template
from llm_key_guard.reporter import create_console_report, create_json_report, post_slack_report
from llm_key_guard.utils import load_config, normalize_path, validate_env_file
from llm_key_guard.banners import print_main_banner, print_command_banner

app = typer.Typer(
    name="llm-key-guard",
    help="LLM Key Guard - Detection and validation of AI API keys",
    add_completion=False,
)

console = Console()

def check_and_install_dependencies() -> None:
    """Check for required dependencies and install them if missing."""
    missing_packages = []
    
    # Check for python-dotenv
    if importlib.util.find_spec("dotenv") is None:
        missing_packages.append("python-dotenv")
    
    # Install missing packages if any
    if missing_packages:
        console.print("[yellow]Installing missing dependencies...[/yellow]")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            console.print("[green]Dependencies installed successfully![/green]")
            
            # Force reload modules
            for package in missing_packages:
                if package == "python-dotenv":
                    try:
                        importlib.reload(importlib.import_module("dotenv"))
                    except (ImportError, AttributeError):
                        pass
        except subprocess.CalledProcessError:
            console.print("[red]Failed to install dependencies. Please install them manually:[/red]")
            console.print(f"[cyan]pip install {' '.join(missing_packages)}[/cyan]")

def show_welcome():
    """Show welcome message and basic usage instructions."""
    print_main_banner(console)
    
    # Create instructions table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Command", style="cyan")
    table.add_column("Description")
    table.add_column("Example", style="green")
    
    table.add_row(
        "scan", 
        "Scan files, Slack or GitHub for directory exposed API keys", 
        "llm-key-guard scan ."
    )
    table.add_row(
        "git-history", 
        "Scan git history for API keys", 
        "llm-key-guard git-history"
    )
    table.add_row(
        "git-diff", 
        "Compare branches for API keys", 
        "llm-key-guard git-diff --base main"
    )
    table.add_row(
        "setup", 
        "Create configuration files for API keys", 
        "llm-key-guard setup"
    )
    table.add_row(
        "version", 
        "Show version information", 
        "llm-key-guard version"
    )
    table.add_row(
        "help", 
        "Show detailed help", 
        "llm-key-guard help"
    )
    
    console.print(table)
    console.print("\n[bold]For command-specific help:[/bold]")
    console.print("  llm-key-guard [command] --help")
    
    # Quick start guide
    console.print("\n[bold cyan]Quick Start:[/bold cyan]")
    console.print("1. Set up configuration files:")
    console.print("   [green]llm-key-guard setup[/green]")
    console.print("2. To scan your current directory for API keys:")
    console.print("   [green]llm-key-guard scan .[/green]")
    console.print("3. To validate found keys against provider APIs:")
    console.print("   [green]llm-key-guard scan . --validate[/green]")
    console.print("4. To scan git history for API keys:")
    console.print("   [green]llm-key-guard git-history[/green]")
    
    # Add LinkedIn info at the bottom
    console.print("\n[blue]Created by Gabriel Jabour | https://www.linkedin.com/in/gjabour/[/blue]")


@app.command("help")
def show_help():
    """Show help information for all commands."""
    print_command_banner("help", console)
    
    console.print("[bold cyan]LLM Key Guard[/bold cyan] - A security tool to detect and validate API keys in your code and repositories")
    console.print("\n[bold]Available Commands:[/bold]")
    
    # Create commands table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Command", style="cyan")
    table.add_column("Description")
    
    table.add_row("scan", "Scan for API keys in files, Slack or GitHub")
    table.add_row("git-history", "Scan git history for API keys")
    table.add_row("git-diff", "Scan git diff between branches for API keys")
    table.add_row("setup", "Create configuration files for API keys")
    table.add_row("version", "Show version information")
    table.add_row("help", "Show this help message")
    
    console.print(table)
    
    console.print("\n[bold]Usage Examples:[/bold]")
    console.print("  [green]llm-key-guard setup[/green]                      # Set up configuration files")
    console.print("  [green]llm-key-guard scan .[/green]                    # Scan current directory")
    console.print("  [green]llm-key-guard scan /path/to/project[/green]     # Scan specific directory")
    console.print("  [green]llm-key-guard scan --validate[/green]           # Scan and validate keys")
    console.print("  [green]llm-key-guard git-history[/green]               # Scan git history")
    console.print("  [green]llm-key-guard git-diff --base main[/green]      # Compare branches")
    
    console.print("\n[bold]For Command-Specific Help:[/bold]")
    console.print("  [green]llm-key-guard setup --help[/green]")
    console.print("  [green]llm-key-guard scan --help[/green]")
    console.print("  [green]llm-key-guard git-history --help[/green]")
    console.print("  [green]llm-key-guard git-diff --help[/green]")
    
    # Add LinkedIn info at the bottom
    console.print("\n[blue]Created by Gabriel Jabour | https://www.linkedin.com/in/gjabour/[/blue]")


@app.command("version")
def version():
    """Show version information."""
    print_command_banner("version", console)
    console.print(f"[bold]LLM Key Guard[/bold] version: [green]{__version__}[/green]")
    console.print("\n[blue]Created by Gabriel Jabour | https://www.linkedin.com/in/gjabour/[/blue]")


def clear_progress(progress):
    """Clear all tasks from a progress bar."""
    try:
        tasks = list(progress.task_ids)
        for task_id in tasks:
            progress.remove_task(task_id)
    except Exception:
        # Ignore errors
        pass

def with_progress(progress, description, total=None):
    """Create a new task with the given description and clean up previous tasks."""
    clear_progress(progress)
    return progress.add_task(description, total=total)

@app.command("scan")
def scan(
    path: Optional[str] = typer.Argument(
        None,
        help="Path to scan for API keys. If not provided, must use --slack-channel or --github-actions",
    ),
    slack_channel: Optional[str] = typer.Option(
        None,
        "--slack-channel",
        "-s",
        help="Slack channel to scan (e.g. '#dev')",
    ),
    github_actions: Optional[str] = typer.Option(
        None,
        "--github-actions",
        "-g",
        help="GitHub repo to scan in format 'owner/repo'",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        "-v",
        help="Validate found API keys against provider APIs",
    ),
    skip_admin_prompt: bool = typer.Option(
        False,
        "--skip-admin-prompt",
        help="Skip prompting for admin keys if they're not configured",
    ),
    json_output: Optional[str] = typer.Option(
        None,
        "--json",
        "-j",
        help="Save results to JSON file",
    ),
    slack_report: bool = typer.Option(
        False,
        "--slack-report",
        help="Post results to Slack channel",
    ),
    slack_report_channel: Optional[str] = typer.Option(
        None,
        "--slack-report-channel",
        help="Slack channel to post report to (default: same as scanned channel)",
    ),
    severity: str = typer.Option(
        "low",
        "--severity",
        "-S",
        help="Minimum severity level to include (low, medium, high)",
    ),
    no_git_ignore: bool = typer.Option(
        False,
        "--no-git-ignore",
        help="Don't respect .gitignore files when scanning directories",
    ),
    threads: int = typer.Option(
        1,
        "--threads",
        "-t",
        help="Number of threads to use for validation",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Purely informational flag, kept for backwards compatibility",
    ),
):
    """Scan for leaked API keys in files, Slack, or GitHub Actions."""
    # Create console
    console = Console()
    
    # Initialize valid_count to avoid undefined variable error
    valid_count = 0
    
    # Create shared progress instance for all operations
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
        TimeRemainingColumn(),
        console=console,
        auto_refresh=False,  # Prevent auto-refresh to avoid flickering
        refresh_per_second=5  # Limit refresh rate
    )
    
    # Display banner
    print_command_banner("scan", console)
    
    # Initial validation
    if not path and not slack_channel and not github_actions:
        console.print("[bold red]Error:[/bold red] Must provide a path, slack channel, or GitHub repo")
        raise typer.Exit(code=1)
    
    # Parse severity
    try:
        min_confidence = getattr(Confidence, severity.upper())
    except AttributeError:
        console.print(f"[bold red]Error:[/bold red] Invalid severity '{severity}', must be low, medium, or high")
        raise typer.Exit(code=1)
    
    # Initialize findings list
    findings: List[KeyFinding] = []
    
    # Scan filesystem
    if path:
        console.print(f"[bold]Scanning directory:[/bold] {path}")
        scan_path = normalize_path(path)
        
        if not scan_path.exists():
            console.print(f"[bold red]Error:[/bold red] Path does not exist: {scan_path}")
            raise typer.Exit(code=1)
            
        # Detect by scanning files
        with progress as progress_ctx:
            task = with_progress(progress, "[cyan]Scanning files...", total=None)
            for finding in scan_directory(
                scan_path, 
                respect_gitignore=not no_git_ignore, 
                show_progress=True,
                threads=threads,
                progress=progress
            ):
                findings.append(finding)
                
            progress.update(task, description="[green]File scanning complete[/green]", visible=False)
            progress.refresh()
            
        console.print(f"[bold green]Found {len(findings)} potential API keys[/bold green]")
    
    # Scan Slack
    if slack_channel:
        console.print(f"[bold]Scanning Slack channel:[/bold] {slack_channel}")
        
        # Check for Slack token
        slack_token = os.environ.get("SLACK_API_TOKEN")
        if not slack_token:
            console.print("[bold red]Error:[/bold red] SLACK_API_TOKEN environment variable not set")
            raise typer.Exit(code=1)
            
        try:
            with progress as progress_ctx:
                task = with_progress(progress, "[cyan]Scanning Slack messages...", total=None)
                slack_scanner = SlackScanner(slack_token)
                slack_findings = list(slack_scanner.scan_channel(slack_channel))
                findings.extend(slack_findings)
                progress.update(task, completed=100)
            console.print(f"[bold green]Found {len(slack_findings)} potential API keys in Slack[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error scanning Slack:[/bold red] {str(e)}")
            raise typer.Exit(code=1)
    
    # Scan GitHub Actions
    if github_actions:
        console.print(f"[bold]Scanning GitHub Actions in repo:[/bold] {github_actions}")
        
        try:
            # Check for GitHub token in env var for private repos
            github_token = os.environ.get("GITHUB_TOKEN")
            with progress as progress_ctx:
                task = with_progress(progress, "[cyan]Scanning GitHub Actions...", total=None)
                github_findings = list(scan_github_actions(github_actions, token=github_token))
                findings.extend(github_findings)
                progress.update(task, completed=100)
            console.print(f"[bold green]Found {len(github_findings)} potential API keys in GitHub Actions[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error scanning GitHub Actions:[/bold red] {str(e)}")
            raise typer.Exit(code=1)
    
    # Validate keys if requested
    if validate:
        console.print("[bold]Validating API keys...[/bold]")
        validator = KeyValidator()
        with progress as progress_ctx:
            task = with_progress(progress, "[cyan]Validating keys[/cyan] 🔑", total=len(findings))
            
            # Create a custom progress callback
            def validation_callback(finding=None):
                progress.update(task, advance=1)
                if finding:
                    provider = finding.provider.value
                    key_preview = finding.key[:6] + "..." + finding.key[-4:]
                    description = f"[cyan]Validating [bold]{provider}[/bold] key[/cyan] {key_preview} 🔑"
                    progress.update(task, description=description)
                progress.refresh()
            
            findings = validator.validate_findings(findings, progress_callback=validation_callback)
        
        # Count valid keys
        valid_count = sum(1 for f in findings if f.valid is True)
        console.print(f"[bold]Validation complete:[/bold] {valid_count} valid keys found")
    
    # Create console report
    console_report = create_console_report(
        findings=findings,
        validated=validate,
        min_confidence=min_confidence
    )
    
    console.print()
    if not findings:
        console.print("[green]✓ No API keys found[/green]")
        console.print("[blue]Scan completed successfully. Your code is clean![/blue]")
    else:
        console.print(console_report)
    
    # Create JSON report if requested
    if json_output:
        create_json_report(findings, json_output, min_confidence)
        console.print(f"[bold green]JSON report saved to:[/bold green] {json_output}")
    
    # Post to Slack if requested
    if slack_report:
        slack_token = os.environ.get("SLACK_API_TOKEN")
        if not slack_token:
            console.print("[bold red]Error:[/bold red] SLACK_API_TOKEN environment variable not set")
            raise typer.Exit(code=1)
        
        report_channel = slack_report_channel or slack_channel
        if not report_channel:
            console.print("[bold red]Error:[/bold red] Must specify --slack-report-channel when not scanning Slack")
            raise typer.Exit(code=1)
            
        console.print(f"[bold]Posting report to Slack channel:[/bold] {report_channel}")
        success = post_slack_report(findings, slack_token, report_channel, min_confidence)
        
        if success:
            console.print("[bold green]Report posted to Slack successfully[/bold green]")
    
    # Show next steps guidance
    console.print("\n[bold cyan]Next Steps:[/bold cyan]")
    if len(findings) > 0 and not validate:
        console.print("- Validate found keys to check if they are active:")
        console.print("  [green]llm-key-guard scan . --validate[/green]")
    else:
        console.print("- Scan regularly to maintain security")
        console.print("- Consider setting up automated scans using CI/CD")


@app.command("git-history")
def git_history(
    repo: str = typer.Argument(
        None,
        help="Repository path to scan for API keys",
    ),
    max_commits: int = typer.Option(
        None,
        "--max-commits",
        help="Maximum number of commits to scan",
    ),
    branch: str = typer.Option(
        "HEAD",
        "--branch",
        help="Git branch to scan",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Validate found API keys against provider APIs",
    ),
    confidence: str = typer.Option(
        "low",
        "--confidence",
        help="Minimum confidence level to include (low, medium, high)",
    ),
    json_output: Optional[str] = typer.Option(
        None,
        "--json",
        "-j",
        help="Save results to JSON file",
    ),
    html_output: Optional[str] = typer.Option(
        None,
        "--html",
        help="Save results to HTML file",
    ),
):
    """Scan git history for leaked API keys."""
    # Create console
    console = Console()
    
    # Create shared progress instance for all operations
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
        TimeRemainingColumn(),
        console=console
    )
    
    # Display the git-history banner
    print_command_banner("git-history", console)
    
    # Parse confidence
    try:
        min_confidence = getattr(Confidence, confidence.upper())
    except AttributeError:
        console.print(f"[bold red]Error:[/bold red] Invalid confidence '{confidence}', must be low, medium, or high")
        raise typer.Exit(code=1)
    
    # Run git history scan
    findings = list(scan_git_history(
        repo_path=repo,
        max_commits=max_commits,
        branch=branch,
    ))
    
    console.print(f"[bold green]Found {len(findings)} potential API keys[/bold green]")
    
    # Validate keys if requested
    if validate:
        console.print("[bold]Validating API keys...[/bold]")
        validator = KeyValidator()
        with progress as progress_ctx:
            task = with_progress(progress, "[cyan]Validating keys[/cyan] 🔑", total=len(findings))
            
            # Create a custom progress callback
            def validation_callback(finding=None):
                progress.update(task, advance=1)
                if finding:
                    provider = finding.provider.value
                    key_preview = finding.key[:6] + "..." + finding.key[-4:]
                    description = f"[cyan]Validating [bold]{provider}[/bold] key[/cyan] {key_preview} 🔑"
                    progress.update(task, description=description)
                progress.refresh()
            
            findings = validator.validate_findings(findings, progress_callback=validation_callback)
        
        # Count valid keys
        valid_count = sum(1 for f in findings if f.valid is True)
        console.print(f"[bold]Validation complete:[/bold] {valid_count} valid keys found")
    
    # Create console report
    console_report = create_console_report(
        findings=findings,
        validated=validate,
        min_confidence=min_confidence
    )
    
    console.print()
    if not findings:
        console.print("[green]✓ No API keys found[/green]")
        console.print("[blue]Scan completed successfully. Your code is clean![/blue]")
    else:
        console.print(console_report)
    
    # Generate JSON report if requested
    if json_output:
        create_json_report(findings, json_output, min_confidence)
    
    # Generate HTML report if requested
    if html_output:
        try:
            from llm_key_guard.exporter import create_html_report
            create_html_report(
                findings, 
                html_output, 
                validated=validate,
                min_confidence=min_confidence
            )
        except ImportError:
            console.print("Error: HTML export module not available", file=sys.stderr)
    
    # Exit with status code based on findings
    valid_count = sum(1 for f in findings if f.valid is True)
    sys.exit(1 if valid_count > 0 else 0)


@app.command("git-diff")
def git_diff(
    repo: str = typer.Argument(
        None,
        help="Repository path to scan for API keys",
    ),
    base: str = typer.Option(
        "main",
        "--base",
        help="Base branch to compare",
    ),
    compare: str = typer.Option(
        "HEAD",
        "--compare",
        help="Compare branch",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Validate found API keys against provider APIs",
    ),
    confidence: str = typer.Option(
        "low",
        "--confidence",
        help="Minimum confidence level to include (low, medium, high)",
    ),
    json_output: Optional[str] = typer.Option(
        None,
        "--json",
        "-j",
        help="Save results to JSON file",
    ),
    html_output: Optional[str] = typer.Option(
        None,
        "--html",
        help="Save results to HTML file",
    ),
):
    """Scan git diff between branches for leaked API keys."""
    # Create console
    console = Console()
    
    # Create shared progress instance for all operations
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
        TimeRemainingColumn(),
        console=console
    )
    
    # Display the git-diff banner
    print_command_banner("git-diff", console)
    
    # Parse confidence
    try:
        min_confidence = getattr(Confidence, confidence.upper())
    except AttributeError:
        console.print(f"[bold red]Error:[/bold red] Invalid confidence '{confidence}', must be low, medium, or high")
        raise typer.Exit(code=1)
    
    # Run git diff scan
    findings = list(scan_git_branch_comparison(
        repo_path=repo,
        base_branch=base,
        compare_branch=compare,
    ))
    
    console.print(f"[bold green]Found {len(findings)} potential API keys[/bold green]")
    
    # Validate keys if requested
    if validate:
        console.print("[bold]Validating API keys...[/bold]")
        validator = KeyValidator()
        with progress as progress_ctx:
            task = with_progress(progress, "[cyan]Validating keys[/cyan] 🔑", total=len(findings))
            
            # Create a custom progress callback
            def validation_callback(finding=None):
                progress.update(task, advance=1)
                if finding:
                    provider = finding.provider.value
                    key_preview = finding.key[:6] + "..." + finding.key[-4:]
                    description = f"[cyan]Validating [bold]{provider}[/bold] key[/cyan] {key_preview} 🔑"
                    progress.update(task, description=description)
                progress.refresh()
            
            findings = validator.validate_findings(findings, progress_callback=validation_callback)
        
        # Count valid keys
        valid_count = sum(1 for f in findings if f.valid is True)
        console.print(f"[bold]Validation complete:[/bold] {valid_count} valid keys found")
    
    # Create console report
    console_report = create_console_report(
        findings=findings,
        validated=validate,
        min_confidence=min_confidence
    )
    
    console.print()
    if not findings:
        console.print("[green]✓ No API keys found[/green]")
        console.print("[blue]Scan completed successfully. Your code is clean![/blue]")
    else:
        console.print(console_report)
    
    # Generate JSON report if requested
    if json_output:
        create_json_report(findings, json_output, min_confidence)
    
    # Generate HTML report if requested
    if html_output:
        try:
            from llm_key_guard.exporter import create_html_report
            create_html_report(
                findings, 
                html_output, 
                validated=validate,
                min_confidence=min_confidence
            )
        except ImportError:
            console.print("Error: HTML export module not available", file=sys.stderr)
    
    # Exit with status code based on findings
    valid_count = sum(1 for f in findings if f.valid is True)
    sys.exit(1 if valid_count > 0 else 0)


@app.command("setup")
def setup(
    target_dir: Optional[str] = typer.Argument(
        ".",
        help="Directory where to create the .env file",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force overwrite existing .env.example file",
    ),
    validate: bool = typer.Option(
        True,
        "--validate/--no-validate",
        help="Validate the .env file after setup",
    ),
):
    """Create configuration files for API keys."""
    print_command_banner("setup", console)
    
    # Check for required dependencies first
    check_and_install_dependencies()
    
    # Change to target directory
    target_path = normalize_path(target_dir)
    if target_path != Path.cwd():
        try:
            os.chdir(target_path)
            console.print(f"[yellow]Changed working directory to:[/yellow] {target_path}")
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            console.print(f"[bold red]Error:[/bold red] Invalid target directory: {target_path}")
            return
            
    # Create the ENV template file
    env_template_file = create_env_template()
    console.print(f"\n[green]Setup completed![/green]")
    
    # Check and validate .env file if it exists
    if validate:
        console.print("\n[bold cyan]Validating .env file...[/bold cyan]")
        dotenv_path = Path(".env")
        
        if not dotenv_path.exists():
            console.print("[yellow]The .env file doesn't exist. Please edit the created .env file and add your keys.[/yellow]")
            return
            
        # Validate the .env file
        validation_result = validate_env_file(dotenv_path)
        
        if validation_result["errors"]:
            console.print("[bold red]Errors found in .env file:[/bold red]")
            for error in validation_result["errors"]:
                console.print(f"[red]• {error}[/red]")
                
        if validation_result["warnings"]:
            console.print("[bold yellow]Warnings found in .env file:[/bold yellow]")
            for warning in validation_result["warnings"]:
                console.print(f"[yellow]• {warning}[/yellow]")
                
        if not validation_result["errors"] and not validation_result["warnings"]:
            console.print("[bold green]The .env file looks good![/bold green]")
        else:
            console.print("\n[cyan]Please edit your .env file to fix these issues and ensure proper functionality.[/cyan]")


def main():
    """Command entrypoint."""
    try:
        # Check for required dependencies before running any command
        check_and_install_dependencies()
        
        # If no arguments, show welcome message with instructions
        if len(sys.argv) == 1:
            show_welcome()
            return
            
        # Run the CLI app
        app()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 