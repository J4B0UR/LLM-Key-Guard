"""Validator for API keys to check if they are valid."""

import time
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union, Callable

import requests

from llm_key_guard.detectors import KeyFinding, Provider


class KeyStatus(Enum):
    """Status of an API key."""
    VALID = "Valid"
    INVALID = "Invalid"
    EXPIRED = "Expired"
    UNKNOWN = "Unknown"


# Default endpoints for key validation
VALIDATION_ENDPOINTS = {
    Provider.OPENAI: "https://api.openai.com/v1/models",
    Provider.ANTHROPIC: "https://api.anthropic.com/v1/messages",
    Provider.AZURE: "https://management.azure.com/subscriptions?api-version=2020-01-01",
    Provider.GEMINI: "https://generativelanguage.googleapis.com/v1beta/models",
    Provider.HUGGINGFACE: "https://huggingface.co/api/whoami-v2",
    Provider.COHERE: "https://api.cohere.ai/v1/models",
    Provider.MISTRAL: "https://api.mistral.ai/v1/models",
}


# Authentication header formats
AUTH_HEADERS = {
    Provider.OPENAI: lambda key: {"Authorization": f"Bearer {key}"},
    Provider.ANTHROPIC: lambda key: {"x-api-key": key},
    Provider.AZURE: lambda key: {"Authorization": f"Bearer {key}"},
    Provider.GEMINI: lambda key: {"X-Goog-Api-Key": key},
    Provider.HUGGINGFACE: lambda key: {"Authorization": f"Bearer {key}"},
    Provider.COHERE: lambda key: {"Authorization": f"Bearer {key}"},
    Provider.MISTRAL: lambda key: {"Authorization": f"Bearer {key}"},
}


# Rate limiting configuration (requests per minute)
RATE_LIMITS = {
    Provider.OPENAI: 60,
    Provider.ANTHROPIC: 60,
    Provider.AZURE: 30,
    Provider.GEMINI: 60,
    Provider.HUGGINGFACE: 30,
    Provider.COHERE: 60,
    Provider.MISTRAL: 60,
    Provider.GENERIC: 10,
}


def validate_key(finding: KeyFinding, timeout: int = 5) -> KeyStatus:
    """Validate if an API key is valid by making a test request.
    
    Args:
        finding: KeyFinding object with provider and key
        timeout: Request timeout in seconds
        
    Returns:
        KeyStatus enum value
    """
    # Skip validation for generic keys
    if finding.provider == Provider.GENERIC:
        return KeyStatus.UNKNOWN
    
    # Provider-specific format validation before making API calls
    if finding.provider == Provider.OPENAI:
        # Check OpenAI key format
        if not (finding.key.startswith("sk-") and len(finding.key) >= 40):
            return KeyStatus.INVALID
    elif finding.provider == Provider.ANTHROPIC:
        # Check Anthropic key format
        if not finding.key.startswith("sk-ant-"):
            return KeyStatus.INVALID
    elif finding.provider == Provider.HUGGINGFACE:
        # Check HuggingFace key format
        if not finding.key.startswith("hf_"):
            return KeyStatus.INVALID
    elif finding.provider == Provider.GEMINI:
        # Check Gemini key format
        if not finding.key.startswith("AIza"):
            return KeyStatus.INVALID
    
    # Get endpoint and auth format
    endpoint = VALIDATION_ENDPOINTS.get(finding.provider)
    auth_header_func = AUTH_HEADERS.get(finding.provider)
    
    if not endpoint or not auth_header_func:
        return KeyStatus.UNKNOWN
    
    # For test keys that contain obvious patterns, mark as invalid without making API call
    lower_key = finding.key.lower()
    if any(pattern in lower_key for pattern in ["test", "example", "fake", "demo", "sample", "placeholder"]):
        return KeyStatus.INVALID
    
    # Check if the key looks like a placeholder or test key
    if finding.key.count("0") > len(finding.key) * 0.4:  # More than 40% zeros
        return KeyStatus.INVALID
    
    # Now make the actual API call
    try:
        headers = auth_header_func(finding.key)
        
        response = requests.get(endpoint, headers=headers, timeout=timeout)
        
        # Handle response based on status code
        if response.status_code == 200:
            # Extra validation for OpenAI - check if the response contains expected content
            if finding.provider == Provider.OPENAI:
                try:
                    data = response.json()
                    if not data.get("data") or not isinstance(data.get("data"), list):
                        return KeyStatus.INVALID
                except:
                    return KeyStatus.INVALID
            return KeyStatus.VALID
        elif response.status_code == 401:
            return KeyStatus.INVALID
        elif response.status_code == 403:
            # Some providers return 403 for expired keys
            if "expired" in response.text.lower():
                return KeyStatus.EXPIRED
            return KeyStatus.VALID  # Key is valid but lacks permissions
        else:
            return KeyStatus.UNKNOWN
            
    except (requests.RequestException, Exception):
        # Network errors, timeouts, etc.
        return KeyStatus.UNKNOWN


class KeyValidator:
    """Validate API keys while respecting rate limits."""
    
    def __init__(self):
        """Initialize the validator with rate limiting state."""
        self.last_request_time: Dict[Provider, float] = {}
        self.request_count: Dict[Provider, int] = {}
        
    def _respect_rate_limit(self, provider: Provider):
        """Ensure we don't exceed rate limits for a provider."""
        current_time = time.time()
        
        # Initialize if first request
        if provider not in self.last_request_time:
            self.last_request_time[provider] = current_time
            self.request_count[provider] = 0
            return
            
        # Check if we're in a new minute
        time_diff = current_time - self.last_request_time[provider]
        if time_diff > 60:
            # Reset for new minute
            self.last_request_time[provider] = current_time
            self.request_count[provider] = 0
            return
            
        # Check if we've hit the limit
        limit = RATE_LIMITS.get(provider, 10)  # Default to 10/min
        if self.request_count[provider] >= limit:
            # Sleep until we can make another request
            sleep_time = 60 - time_diff
            if sleep_time > 0:
                time.sleep(sleep_time)
                self.last_request_time[provider] = time.time()
                self.request_count[provider] = 0
                
        # Update request count
        self.request_count[provider] = self.request_count[provider] + 1
        
    def validate(self, finding: KeyFinding, timeout: int = 5) -> KeyStatus:
        """Validate a key while respecting rate limits."""
        self._respect_rate_limit(finding.provider)
        return validate_key(finding, timeout)
        
    def validate_findings(
        self, 
        findings: List[KeyFinding], 
        show_progress: bool = True,
        timeout: int = 5,
        progress_callback: Optional[Callable] = None
    ) -> List[KeyFinding]:
        """Validate a list of findings.
        
        Args:
            findings: List of KeyFinding objects to validate
            show_progress: Whether to show a progress bar
            timeout: Request timeout in seconds
            progress_callback: Optional callback function to track progress
            
        Returns:
            List of validated KeyFinding objects
        """
        if not findings:
            return []
        
        for i, finding in enumerate(findings):
            # Skip keys with confidence too low to be worth validating
            from llm_key_guard.detectors import Confidence
            if finding.confidence == Confidence.LOW:
                continue
                
            status = self.validate(finding, timeout)
            finding.valid = status == KeyStatus.VALID
            
            # Call progress callback if provided
            if progress_callback:
                progress_callback(finding)
            
        return findings 