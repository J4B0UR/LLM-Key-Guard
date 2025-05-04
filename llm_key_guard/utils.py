"""Utility functions and helpers for LLM Key Guard."""

import os
import time
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yaml
from rich.console import Console


def ensure_dir(directory: Union[str, Path]) -> None:
    """Ensure a directory exists."""
    Path(directory).mkdir(parents=True, exist_ok=True)


def load_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Load configuration from file.
    
    Args:
        config_path: Path to config file. If None, will try default locations.
        
    Returns:
        Dictionary of configuration values
    """
    # Default config locations
    default_locations = [
        Path.cwd() / ".llmkg.yml",
        Path.cwd() / ".llmkg.yaml",
        Path.home() / ".llmkg" / "config.yml",
        Path.home() / ".config" / "llm-key-guard" / "config.yml",
    ]
    
    # If config path provided, try that first
    if config_path:
        config_path = Path(config_path)
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    return yaml.safe_load(f) or {}
            except (yaml.YAMLError, IOError):
                pass
    
    # Try default locations
    for path in default_locations:
        if path.exists():
            try:
                with open(path, "r") as f:
                    return yaml.safe_load(f) or {}
            except (yaml.YAMLError, IOError):
                continue
    
    # Return empty config if no config file found
    return {}


def save_config(config: Dict[str, Any], config_path: Optional[Union[str, Path]] = None) -> bool:
    """Save configuration to file.
    
    Args:
        config: Configuration dictionary to save
        config_path: Path to save config to. If None, will use default location.
        
    Returns:
        True if successful, False otherwise
    """
    # Default config location
    if not config_path:
        config_dir = Path.home() / ".llmkg"
        ensure_dir(config_dir)
        config_path = config_dir / "config.yml"
    else:
        config_path = Path(config_path)
        ensure_dir(config_path.parent)
    
    try:
        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        return True
    except IOError:
        return False


def load_credentials(provider: Optional[str] = None) -> Dict[str, str]:
    """Load credentials from file.
    
    Args:
        provider: Optional provider name to load credentials for
        
    Returns:
        Dictionary of credentials
    """
    creds_path = Path.home() / ".llmkg" / "creds.yml"
    
    if not creds_path.exists():
        return {}
    
    try:
        with open(creds_path, "r") as f:
            creds = yaml.safe_load(f) or {}
        
        if provider:
            return {provider: creds.get(provider, "")} if provider in creds else {}
        else:
            return creds
    except (yaml.YAMLError, IOError):
        return {}


def get_cache_dir() -> Path:
    """Get cache directory for storing temporary data."""
    cache_dir = Path.home() / ".cache" / "llm-key-guard"
    ensure_dir(cache_dir)
    return cache_dir


def normalize_path(path: Union[str, Path]) -> Path:
    """Normalize a path, expanding ~ and environment variables."""
    return Path(os.path.expandvars(os.path.expanduser(str(path))))


def validate_env_file(env_path: Union[str, Path] = ".env") -> Dict[str, List[str]]:
    """Validate .env file and check for common issues.
    
    Args:
        env_path: Path to .env file
        
    Returns:
        Dictionary with lists of warnings and errors
    """
    console = Console()
    env_path = Path(env_path)
    result = {
        "warnings": [],
        "errors": [],
    }
    
    if not env_path.exists():
        result["errors"].append(f"The .env file does not exist at {env_path}")
        return result
    
    try:
        # Read the .env file
        with open(env_path, "r") as f:
            env_content = f.read()
            
        # Check for empty file
        if not env_content.strip():
            result["errors"].append("The .env file is empty")
            return result
            
        # Check for template values still in place
        template_patterns = [
            r"your_\w+_key_here",
            r"your_\w+_token_here",
        ]
        
        for line in env_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            if "=" not in line:
                result["warnings"].append(f"Line missing '=' separator: {line}")
                continue
                
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            
            # Skip empty values
            if not value:
                result["warnings"].append(f"Empty value for key: {key}")
                continue
                
            # Check for template values
            for pattern in template_patterns:
                if re.search(pattern, value):
                    result["warnings"].append(f"Template value still in place for key: {key}")
                    break
                    
            # Check for quotes that might not be needed
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                if '"' in value[1:-1] or "'" in value[1:-1]:
                    # Quotes are probably needed for escaping
                    pass
                else:
                    result["warnings"].append(f"Unnecessary quotes in value for key: {key}")
        
        return result
    except Exception as e:
        result["errors"].append(f"Error reading .env file: {str(e)}")
        return result


def rate_limit(func: callable, rate_limit_per_min: int = 60) -> callable:
    """Decorator to rate limit a function."""
    last_call_time = 0
    calls_this_minute = 0
    
    def wrapper(*args, **kwargs):
        nonlocal last_call_time, calls_this_minute
        current_time = time.time()
        
        # Reset counter if more than a minute has passed
        if current_time - last_call_time > 60:
            calls_this_minute = 0
            last_call_time = current_time
        
        # Check if we've hit the limit
        if calls_this_minute >= rate_limit_per_min:
            # Sleep until we can make another request
            sleep_time = 60 - (current_time - last_call_time)
            if sleep_time > 0:
                time.sleep(sleep_time)
                calls_this_minute = 0
                last_call_time = time.time()
        
        # Update counter
        calls_this_minute += 1
        
        # Call the function
        return func(*args, **kwargs)
    
    return wrapper 