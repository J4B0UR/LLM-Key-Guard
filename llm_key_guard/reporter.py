"""Reporter module for generating reports in different formats."""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Set, TextIO, Union

import rich
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress
import requests

from llm_key_guard.detectors import Confidence, KeyFinding, Provider


def create_console_report(
    findings: List[KeyFinding],
    validated: bool = False,
    min_confidence: Confidence = Confidence.LOW,
    file: Optional[TextIO] = None
) -> None:
    """Create a rich console report of findings.
    
    Args:
        findings: List of KeyFinding objects
        validated: Whether keys have been validated
        min_confidence: Minimum confidence level to include
        file: Optional file to write to
    """
    console = Console(file=file)
    
    # Filter by confidence
    filtered_findings = [
        f for f in findings 
        if f.confidence >= min_confidence
    ]
    
    # Group by provider
    providers = {}
    for finding in filtered_findings:
        if finding.provider not in providers:
            providers[finding.provider] = []
        providers[finding.provider].append(finding)
    
    # Summary
    console.print()
    console.print(Panel.fit(
        f"[bold]LLM Key Guard Report[/bold] - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        border_style="blue"
    ))
    console.print()
    
    # Summary table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Provider")
    table.add_column("Total", justify="right")
    table.add_column("Valid", justify="right")
    
    total_count = len(filtered_findings)
    valid_count = sum(1 for f in filtered_findings if f.valid is True)
    
    for provider, provider_findings in providers.items():
        provider_valid = sum(1 for f in provider_findings if f.valid is True)
        
        table.add_row(
            provider.value,
            str(len(provider_findings)),
            str(provider_valid) if validated else "n/a"
        )
    
    # Add total row
    table.add_row(
        "TOTAL",
        str(total_count),
        str(valid_count) if validated else "n/a",
        style="bold"
    )
    
    console.print(table)
    console.print()
    
    # Detailed findings
    if filtered_findings:
        tree = Tree("[bold]Detailed Findings[/bold]")
        
        for provider, provider_findings in providers.items():
            provider_tree = tree.add(f"[bold]{provider.value}[/bold] ({len(provider_findings)} keys)")
            
            for finding in provider_findings:
                # Determine color and status based on validation status (only if validated)
                if validated:
                    if finding.valid is True:
                        color = "red"
                        status = "VALID"
                    elif finding.valid is False:
                        color = "yellow"
                        status = "INVALID"
                    else:
                        color = "blue"
                        status = finding.confidence.value
                else:
                    # Not validated, just show confidence
                    color = "blue"
                    status = finding.confidence.value
                
                # Format location info
                location = ""
                if finding.file_path:
                    location = f"[dim]{os.path.basename(finding.file_path)}"
                    if finding.line_number:
                        location += f":{finding.line_number}"
                    location += "[/dim]"
                
                # Format context
                context = finding.context
                if len(context) > 80:
                    context = context[:77] + "..."
                
                # Add to tree
                finding_text = Text.from_markup(
                    f"[{color}]{status}[/{color}] {location} {context}"
                )
                provider_tree.add(finding_text)
        
        console.print(tree)
        console.print()
        
        # Recommendations
        if validated and valid_count > 0:
            console.print(Panel(
                "[bold red]ACTION REQUIRED[/bold red]: Valid API keys were found that should be removed immediately.",
                border_style="red"
            ))
        elif total_count > 0 and not validated:
            console.print(Panel(
                "[bold yellow]WARNING[/bold yellow]: Potential API keys were found but have not been validated.",
                border_style="yellow"
            ))
        elif total_count > 0:
            console.print(Panel(
                "[bold yellow]WARNING[/bold yellow]: Potential API keys were found but none appear to be valid.",
                border_style="yellow"
            ))
        else:
            console.print(Panel(
                "[bold green]ALL CLEAR[/bold green]: No API keys were found.",
                border_style="green"
            ))
        
        console.print()
    else:
        console.print(Panel(
            "[bold green]No API keys found matching the specified criteria.[/bold green]",
            border_style="green"
        ))
        console.print()


def create_json_report(
    findings: List[KeyFinding],
    output_file: str,
    min_confidence: Confidence = Confidence.LOW
) -> None:
    """Create a JSON report of findings.
    
    Args:
        findings: List of KeyFinding objects
        output_file: File to write JSON report to
        min_confidence: Minimum confidence level to include
    """
    # Filter by confidence
    filtered_findings = [
        f for f in findings 
        if f.confidence >= min_confidence
    ]
    
    # Convert findings to dictionaries
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": len(filtered_findings),
            "valid": sum(1 for f in filtered_findings if f.valid is True),
            "revoked": sum(1 for f in filtered_findings if f.revoked is True),
            "by_provider": {},
            "by_confidence": {}
        },
        "findings": []
    }
    
    # Build summary
    for finding in filtered_findings:
        provider = finding.provider.value
        confidence = finding.confidence.value
        
        # Update provider summary
        if provider not in report_data["summary"]["by_provider"]:
            report_data["summary"]["by_provider"][provider] = {
                "total": 0, "valid": 0, "revoked": 0
            }
        
        report_data["summary"]["by_provider"][provider]["total"] += 1
        
        if finding.valid is True:
            report_data["summary"]["by_provider"][provider]["valid"] += 1
            
        if finding.revoked is True:
            report_data["summary"]["by_provider"][provider]["revoked"] += 1
        
        # Update confidence summary
        if confidence not in report_data["summary"]["by_confidence"]:
            report_data["summary"]["by_confidence"][confidence] = 0
        report_data["summary"]["by_confidence"][confidence] += 1
        
        # Add finding details
        finding_data = {
            "provider": finding.provider.value,
            "key_prefix": finding.key[:8],  # Only include prefix for security
            "confidence": finding.confidence.value,
            "context": finding.context,
            "valid": finding.valid,
            "revoked": finding.revoked
        }
        
        if finding.file_path:
            finding_data["file_path"] = finding.file_path
            
        if finding.line_number:
            finding_data["line_number"] = finding.line_number
            
        report_data["findings"].append(finding_data)
    
    # Write to file
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=2)
        
    console = Console()
    console.print(f"JSON report written to [bold]{output_file}[/bold]")


def post_slack_report(
    findings: List[KeyFinding],
    slack_token: str,
    channel: str,
    min_confidence: Confidence = Confidence.LOW
) -> bool:
    """Post a report to Slack.
    
    Args:
        findings: List of KeyFinding objects
        slack_token: Slack API token
        channel: Channel to post to (with or without #)
        min_confidence: Minimum confidence level to include
        
    Returns:
        True if successful, False otherwise
    """
    # Filter by confidence
    filtered_findings = [
        f for f in findings 
        if f.confidence >= min_confidence
    ]
    
    # Prepare summary
    total_count = len(filtered_findings)
    valid_count = sum(1 for f in filtered_findings if f.valid is True)
    revoked_count = sum(1 for f in filtered_findings if f.revoked is True)
    
    # Group by provider
    providers = {}
    for finding in filtered_findings:
        if finding.provider not in providers:
            providers[finding.provider] = []
        providers[finding.provider].append(finding)
    
    # Create message blocks
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🔐 LLM Key Guard Report"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Report Date:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Total Keys:* {total_count}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Valid Keys:* {valid_count}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Revoked Keys:* {revoked_count}"
                }
            ]
        },
        {
            "type": "divider"
        }
    ]
    
    # Add provider summaries
    for provider, provider_findings in providers.items():
        provider_valid = sum(1 for f in provider_findings if f.valid is True)
        provider_revoked = sum(1 for f in provider_findings if f.revoked is True)
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{provider.value}*: {len(provider_findings)} keys found, {provider_valid} valid, {provider_revoked} revoked"
            }
        })
    
    # Add alert based on findings
    if valid_count > 0:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "🚨 *ACTION REQUIRED*: Valid API keys were found that should be revoked immediately."
            }
        })
    elif total_count > 0:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "⚠️ *WARNING*: Potential API keys were found but none appear to be valid."
            }
        })
    else:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "✅ *ALL CLEAR*: No API keys were found."
            }
        })
    
    # Add key details for valid keys
    valid_findings = [f for f in filtered_findings if f.valid is True]
    if valid_findings:
        blocks.append({
            "type": "divider"
        })
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Valid Key Details:*"
            }
        })
        
        for finding in valid_findings[:10]:  # Limit to 10 to avoid message size limits
            location = ""
            if finding.file_path:
                location = f"{os.path.basename(finding.file_path)}"
                if finding.line_number:
                    location += f":{finding.line_number}"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{finding.provider.value}* key in {location}\n{finding.context}"
                }
            })
        
        # Add note if we truncated findings
        if len(valid_findings) > 10:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"_...and {len(valid_findings) - 10} more valid keys not shown._"
                }
            })
    
    # Post to Slack
    try:
        # Ensure channel name is properly formatted
        if not channel.startswith('#') and not channel.startswith('C'):
            channel = f"#{channel}"
        
        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {slack_token}",
                "Content-Type": "application/json"
            },
            json={
                "channel": channel,
                "blocks": blocks,
                "text": f"LLM Key Guard found {total_count} potential API keys, {valid_count} valid, {revoked_count} revoked."
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("ok"):
                return True
            else:
                console = Console()
                console.print(f"[bold red]Error posting to Slack:[/bold red] {data.get('error', 'Unknown error')}")
                return False
        else:
            console = Console()
            console.print(f"[bold red]Error posting to Slack:[/bold red] HTTP {response.status_code}")
            return False
            
    except Exception as e:
        console = Console()
        console.print(f"[bold red]Error posting to Slack:[/bold red] {str(e)}")
        return False 