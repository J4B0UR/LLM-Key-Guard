"""Parser for CI/CD configuration files (GitHub Actions, GitLab CI)."""

import os
import yaml
from typing import Dict, Iterator, List, Optional, Set, Union
import requests

from llm_key_guard.detectors import KeyFinding, looks_like_key


def parse_github_actions_workflow(workflow_content: str) -> Iterator[KeyFinding]:
    """Parse a GitHub Actions workflow file for potential API keys."""
    try:
        # Load YAML content
        workflow = yaml.safe_load(workflow_content)
        
        # Check for environment variables in jobs
        if "jobs" in workflow:
            for job_name, job_config in workflow.get("jobs", {}).items():
                # Check env section of job
                for env_name, env_value in job_config.get("env", {}).items():
                    if isinstance(env_value, str):
                        for finding in looks_like_key(env_value):
                            finding.context = f"GitHub Actions job '{job_name}' env var '{env_name}': {finding.context}"
                            yield finding
                
                # Check steps with env variables or run commands
                for step_idx, step in enumerate(job_config.get("steps", [])):
                    # Check step env vars
                    for env_name, env_value in step.get("env", {}).items():
                        if isinstance(env_value, str):
                            for finding in looks_like_key(env_value):
                                finding.context = f"GitHub Actions job '{job_name}' step {step_idx} env var '{env_name}': {finding.context}"
                                yield finding
                    
                    # Check run commands for inline secrets
                    if "run" in step and isinstance(step["run"], str):
                        for finding in looks_like_key(step["run"]):
                            finding.context = f"GitHub Actions job '{job_name}' step {step_idx} run command: {finding.context}"
                            yield finding
        
        # Check workflow-level env vars
        for env_name, env_value in workflow.get("env", {}).items():
            if isinstance(env_value, str):
                for finding in looks_like_key(env_value):
                    finding.context = f"GitHub Actions workflow env var '{env_name}': {finding.context}"
                    yield finding
                    
    except yaml.YAMLError:
        # Return empty for invalid YAML
        return


def parse_gitlab_ci_file(ci_content: str) -> Iterator[KeyFinding]:
    """Parse a GitLab CI configuration file for potential API keys."""
    try:
        # Load YAML content
        ci_config = yaml.safe_load(ci_content)
        
        # Check variables section
        for var_name, var_value in ci_config.get("variables", {}).items():
            if isinstance(var_value, str):
                for finding in looks_like_key(var_value):
                    finding.context = f"GitLab CI variables section '{var_name}': {finding.context}"
                    yield finding
        
        # Check jobs
        for job_name, job_config in ci_config.items():
            # Skip special GitLab CI keys
            if job_name in ["stages", "variables", "workflow", "default", "include"]:
                continue
                
            # Check job variables
            for var_name, var_value in job_config.get("variables", {}).items():
                if isinstance(var_value, str):
                    for finding in looks_like_key(var_value):
                        finding.context = f"GitLab CI job '{job_name}' variable '{var_name}': {finding.context}"
                        yield finding
            
            # Check script commands
            for script_idx, script_line in enumerate(job_config.get("script", [])):
                if isinstance(script_line, str):
                    for finding in looks_like_key(script_line):
                        finding.context = f"GitLab CI job '{job_name}' script line {script_idx}: {finding.context}"
                        yield finding
                        
            # Check before_script and after_script
            for script_type in ["before_script", "after_script"]:
                for script_idx, script_line in enumerate(job_config.get(script_type, [])):
                    if isinstance(script_line, str):
                        for finding in looks_like_key(script_line):
                            finding.context = f"GitLab CI job '{job_name}' {script_type} line {script_idx}: {finding.context}"
                            yield finding
                            
    except yaml.YAMLError:
        # Return empty for invalid YAML
        return


def fetch_github_workflow(repo: str, workflow_file: str, token: Optional[str] = None) -> str:
    """Fetch a GitHub Actions workflow file from a public or private repository.
    
    Args:
        repo: Repository in format "owner/repo"
        workflow_file: Workflow file path (e.g. ".github/workflows/ci.yml")
        token: GitHub API token for private repos
        
    Returns:
        Workflow file content as string
    """
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
        
    # Format URL for GitHub API
    url = f"https://api.github.com/repos/{repo}/contents/{workflow_file}"
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise ValueError(f"Failed to fetch workflow file: {response.status_code} {response.text}")
        
    # GitHub API returns base64 encoded content
    content_data = response.json()
    if "content" not in content_data:
        raise ValueError("Invalid response from GitHub API")
        
    import base64
    content = base64.b64decode(content_data["content"]).decode("utf-8")
    return content


def scan_github_actions(
    repo: str,
    workflow_file: Optional[str] = None,
    token: Optional[str] = None
) -> Iterator[KeyFinding]:
    """Scan GitHub Actions workflows for API keys.
    
    Args:
        repo: Repository in format "owner/repo"
        workflow_file: Optional specific workflow file to scan
        token: GitHub API token for private repos
        
    Yields:
        KeyFinding objects for each detected API key
    """
    # If specific workflow file provided
    if workflow_file:
        content = fetch_github_workflow(repo, workflow_file, token)
        yield from parse_github_actions_workflow(content)
        return
        
    # Otherwise, fetch all workflow files
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
        
    # First check if .github/workflows directory exists
    url = f"https://api.github.com/repos/{repo}/contents/.github/workflows"
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise ValueError(f"Failed to list workflow files: {response.status_code} {response.text}")
        
    # Get all YAML files
    files = response.json()
    for file_info in files:
        if file_info["type"] == "file" and file_info["name"].endswith((".yml", ".yaml")):
            # Get content of each workflow file
            content = fetch_github_workflow(repo, file_info["path"], token)
            yield from parse_github_actions_workflow(content) 