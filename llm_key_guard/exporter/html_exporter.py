"""HTML exporter for LLM Key Guard reports."""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional

from llm_key_guard.detectors import Confidence, KeyFinding, Provider


def _create_html_header(title: str) -> str:
    """Create HTML header with styling."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f7f7f7;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            display: flex;
            align-items: center;
        }}
        h1 span.icon {{
            font-size: 1.5em;
            margin-right: 10px;
        }}
        .summary {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-card {{
            flex: 1;
            min-width: 200px;
            padding: 15px;
            border-radius: 5px;
            background: #f8f9fa;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}
        .summary-card h3 {{
            margin-top: 0;
            color: #3498db;
            font-size: 1.1em;
        }}
        .summary-card p {{
            font-size: 2em;
            font-weight: bold;
            margin: 5px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        table, th, td {{
            border: 1px solid #ddd;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .valid {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .invalid {{
            color: #7f8c8d;
        }}
        .revoked {{
            color: #7E57C2;
            font-weight: bold;
        }}
        .unknown {{
            color: #f39c12;
        }}
        .context {{
            font-family: monospace;
            background: #f8f9fa;
            padding: 8px;
            border-left: 3px solid #3498db;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge-high {{
            background: #e74c3c;
            color: white;
        }}
        .badge-medium {{
            background: #f39c12;
            color: white;
        }}
        .badge-low {{
            background: #95a5a6;
            color: white;
        }}
        .alert {{
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
            border-left: 5px solid;
        }}
        .alert-danger {{
            background-color: #fde8e8;
            border-left-color: #e74c3c;
        }}
        .alert-warning {{
            background-color: #fef6e7;
            border-left-color: #f39c12;
        }}
        .alert-success {{
            background-color: #e8f5e9;
            border-left-color: #27ae60;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        details {{
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }}
        summary {{
            padding: 12px 15px;
            background-color: #f8f9fa;
            cursor: pointer;
            font-weight: bold;
        }}
        details .content {{
            padding: 12px 15px;
        }}
        .key-prefix {{
            font-family: monospace;
            background: #eee;
            padding: 2px 4px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1><span class="icon">🔐</span> LLM Key Guard Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""


def _create_html_footer() -> str:
    """Create HTML footer."""
    return """
        <div class="footer">
            <p>Generated by LLM Key Guard - <a href="https://github.com/seunome/llm-key-guard" target="_blank">https://github.com/seunome/llm-key-guard</a></p>
        </div>
    </div>
</body>
</html>
"""


def _create_summary_section(findings: List[KeyFinding], validated: bool = False) -> str:
    """Create the HTML summary section.
    
    Args:
        findings: List of KeyFinding objects
        validated: Whether keys were validated
        
    Returns:
        HTML string for the summary section
    """
    total_count = len(findings)
    valid_count = sum(1 for f in findings if f.valid is True) if validated else None
    
    # Add summary banner
    summary_html = """
    <div class="summary-section">
        <h2>Key Detection Summary</h2>
        <h3>Overview</h3>
        <div class="summary">
    """
    
    # Add general summary
    summary_html += """
        <div class="summary-card">
            <h3>Total Keys</h3>
            <div class="summary-count">{}</div>
        </div>
    """.format(total_count)
    
    if validated:
        summary_html += """
        <div class="summary-card">
            <h3>Valid Keys</h3>
            <div class="summary-count">{}</div>
        </div>
        """.format(valid_count or 0)
    
    summary_html += """
        </div>
    """

    # Add provider specific tables
    summary_html += """
    <div class="summary-tables">
        <h3>Provider Breakdown</h3>
        <table>
            <tr>
                <th>Provider</th>
                <th>Total</th>
                <th>Confidence</th>
    """
    
    if validated:
        summary_html += "<th>Valid</th>"
    
    summary_html += """
            </tr>
    """
    
    # Group findings by provider
    providers = {}
    for finding in findings:
        provider = finding.provider.value
        if provider not in providers:
            providers[provider] = []
        providers[provider].append(finding)
    
    for provider, provider_findings in sorted(providers.items()):
        provider_valid = sum(1 for f in provider_findings if f.valid is True) if validated else None
        
        # Get the average confidence
        confidence_values = [f.confidence for f in provider_findings]
        avg_confidence = sum(int(c) for c in confidence_values) / len(confidence_values)
        confidence_text = Confidence(int(avg_confidence)).__str__()
        
        summary_html += f"""
            <tr>
                <td>{provider}</td>
                <td>{len(provider_findings)}</td>
                <td>{confidence_text}</td>
        """
        
        if validated:
            summary_html += f"<td>{provider_valid or 0}</td>"
        
        summary_html += """
            </tr>
        """
    
    summary_html += """
            <tr class="total-row">
                <td><strong>Total</strong></td>
                <td><strong>{}</strong></td>
                <td>-</td>
    """.format(total_count)
    
    if validated:
        summary_html += f"<td><strong>{valid_count or 0}</strong></td>"
    
    summary_html += """
            </tr>
        </table>
    </div>
    """
    
    # Add risk assessment
    if validated and valid_count and valid_count > 0:
        summary_html += """
        <div class="risk-warning">
            <div class="risk-title">⚠️ HIGH RISK</div>
            <div class="risk-message">
                <strong>ACTION REQUIRED:</strong> Valid API keys were found that should be revoked immediately.
            </div>
        </div>
        """
    
    summary_html += """
    </div>
    """
    return summary_html


def _create_findings_section(findings: List[KeyFinding], validated: bool = False) -> str:
    """Create the HTML findings section.
    
    Args:
        findings: List of KeyFinding objects
        validated: Whether keys were validated
        
    Returns:
        HTML string for the findings section
    """
    findings_html = """
    <div class="findings-section">
        <h2>Detected API Keys</h2>
        <table class="findings-table">
            <tr>
                <th>Provider</th>
                <th>Confidence</th>
                <th>Key Fragment</th>
                <th>Location</th>
    """
    
    if validated:
        findings_html += "<th>Status</th>"
    
    findings_html += """
            </tr>
    """
    
    for finding in findings:
        # Get key fragment for display
        key_length = len(finding.key)
        key_fragment = finding.key[:4] + "..." + finding.key[-4:] if key_length > 10 else finding.key
        key_full = finding.key
        
        # Set location text
        location_text = "N/A"
        if finding.file_path:
            filename = os.path.basename(finding.file_path)
            if finding.line_number:
                location_text = f"{filename}:{finding.line_number}"
            else:
                location_text = filename
        
        # Set status and class
        status = "N/A"
        status_class = ""
        
        if validated:
            if finding.valid is True:
                status = "VALID"
                status_class = "valid"
            elif finding.valid is False:
                status = "INVALID"
                status_class = "invalid"
        
        findings_html += f"""
            <tr class="finding">
                <td>{finding.provider.value}</td>
                <td>{finding.confidence}</td>
                <td class="key-fragment" title="{key_full}">{key_fragment}</td>
                <td>{location_text}</td>
        """
        
        if validated:
            findings_html += f'<td class="{status_class}">{status}</td>'
        
        findings_html += """
            </tr>
            <tr class="context-row">
                <td colspan="{}">
                    <pre class="context">{}</pre>
                </td>
            </tr>
        """.format("5" if validated else "4", finding.context)
    
    findings_html += """
        </table>
    </div>
    """
    return findings_html


def create_html_report(
    findings: List[KeyFinding],
    output_file: str,
    validated: bool = False,
    min_confidence: int = 1,
) -> str:
    """Create an HTML report of findings.
    
    Args:
        findings: List of KeyFinding objects
        output_file: Path to output HTML file
        validated: Whether keys were validated
        min_confidence: Minimum confidence level (1-3) to include
        
    Returns:
        Path to created HTML file
    """
    # Filter findings by confidence
    filtered_findings = [f for f in findings if int(f.confidence) >= min_confidence]
    
    # Create the HTML content
    html_content = _create_html_header("LLM Key Guard Report")
    html_content += _create_summary_section(filtered_findings, validated)
    html_content += _create_findings_section(filtered_findings, validated)
    html_content += _create_html_footer()
    
    # Write to file
    with open(output_file, "w") as f:
        f.write(html_content)
        
    return output_file 