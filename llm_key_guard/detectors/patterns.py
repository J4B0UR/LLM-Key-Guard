"""Regex patterns and entropy checks for API key detection."""

import re
import math
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, Iterator, List, Optional, Pattern, Tuple, Union


class Confidence(IntEnum):
    """Confidence level for a key finding."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    
    def __str__(self):
        return {
            Confidence.LOW: "Low",
            Confidence.MEDIUM: "Medium",
            Confidence.HIGH: "High"
        }[self]


class Provider(Enum):
    """Supported API key providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    GEMINI = "gemini"
    HUGGINGFACE = "huggingface"
    COHERE = "cohere"
    MISTRAL = "mistral"
    STABILITY = "stability"
    REPLICATE = "replicate"
    CLARIFAI = "clarifai"
    TOGETHER = "together"
    AI21 = "ai21"
    DEEPINFRA = "deepinfra"
    ALEPH_ALPHA = "aleph_alpha"
    GROQ = "groq"
    GENERIC = "generic"


@dataclass
class KeyFinding:
    """Represents a detected API key."""
    provider: Provider
    key: str
    confidence: Confidence
    context: str
    line_number: Optional[int] = None
    file_path: Optional[str] = None
    valid: Optional[bool] = None


# Regex patterns for different providers
PROVIDER_PATTERNS: Dict[Provider, Pattern] = {
    Provider.OPENAI: re.compile(r"(sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9-_]{68,}|sk-admin-[A-Za-z0-9-_]{90,})"),
    Provider.ANTHROPIC: re.compile(r"sk-ant-[A-Za-z0-9]{40}"),
    Provider.AZURE: re.compile(r"(?:azure-api-key-|api-key-azure-)[A-Za-z0-9]{32}"),
    Provider.GEMINI: re.compile(r"AIza[A-Za-z0-9_\-]{35}"),
    Provider.HUGGINGFACE: re.compile(r"hf_[A-Za-z0-9]{34}"),
    Provider.COHERE: re.compile(r"(?:co-|cohere-api-key-)[A-Za-z0-9]{40}"),
    Provider.MISTRAL: re.compile(r"(?:mistral-|mst-)[A-Za-z0-9]{32}"),
    Provider.STABILITY: re.compile(r"sk-[A-Za-z0-9]{48}"),
    Provider.REPLICATE: re.compile(r"r8_[A-Za-z0-9]{40}"),
    Provider.CLARIFAI: re.compile(r"Key-[A-Za-z0-9]{32}"),
    Provider.TOGETHER: re.compile(r"[A-Za-z0-9]{64}"),
    Provider.AI21: re.compile(r"(?:ai21-|ai21j-)[A-Za-z0-9]{32}"),
    Provider.DEEPINFRA: re.compile(r"(?:deepinfra-|di-)[A-Za-z0-9]{40}"),
    Provider.ALEPH_ALPHA: re.compile(r"[A-Za-z0-9]{64}"),
    Provider.GROQ: re.compile(r"gsk_[A-Za-z0-9]{48}"),
    Provider.GENERIC: re.compile(r"(?:api[-_]?key|secret[-_]?key|access[-_]?token)[-_][A-Za-z0-9]{30,90}", re.IGNORECASE),
}

# Additional prefixes to help with detection
PROVIDER_PREFIXES = {
    "sk-ant": Provider.ANTHROPIC,
    "hf_": Provider.HUGGINGFACE,
    "sk-proj-": Provider.OPENAI,
    "sk-admin-": Provider.OPENAI,
    "sk-": [Provider.OPENAI, Provider.STABILITY],
    "AIza": Provider.GEMINI,
    "r8_": Provider.REPLICATE,
    "Key-": Provider.CLARIFAI,
    "gsk_": Provider.GROQ,
    "co-": Provider.COHERE,
    "cohere-api-key-": Provider.COHERE,
    "mistral-": Provider.MISTRAL,
    "mst-": Provider.MISTRAL,
    "ai21-": Provider.AI21,
    "ai21j-": Provider.AI21,
    "azure-api-key-": Provider.AZURE,
    "api-key-azure-": Provider.AZURE,
    "deepinfra-": Provider.DEEPINFRA,
    "di-": Provider.DEEPINFRA,
}


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    
    # Count character frequencies
    char_count = {}
    for char in s:
        if char in char_count:
            char_count[char] += 1
        else:
            char_count[char] = 1
    
    # Calculate entropy using frequency distribution
    length = len(s)
    entropy = 0.0
    for count in char_count.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_character_distribution_score(s: str) -> float:
    """Calculate a score based on character distribution.
    
    API keys typically have a more even distribution of characters
    than regular text or common patterns.
    
    Returns:
        Float between 0-1, where higher values indicate a more even distribution
    """
    if not s or len(s) < 8:
        return 0.0
    
    # Count characters by category
    categories = {
        'lowercase': 0,
        'uppercase': 0,
        'digits': 0,
        'special': 0
    }
    
    for char in s:
        if char.islower():
            categories['lowercase'] += 1
        elif char.isupper():
            categories['uppercase'] += 1
        elif char.isdigit():
            categories['digits'] += 1
        else:
            categories['special'] += 1
    
    # Calculate distribution evenness
    total = len(s)
    category_percentages = [count / total for count in categories.values() if count > 0]
    
    # If all characters are from the same category, score is low
    if len(category_percentages) == 1:
        return 0.3
    
    # Ideal distribution would be even across used categories
    ideal_percentage = 1.0 / len(category_percentages)
    deviations = [abs(p - ideal_percentage) for p in category_percentages]
    average_deviation = sum(deviations) / len(deviations)
    
    # Convert to a score (0-1, where 1 is perfect distribution)
    return 1.0 - average_deviation


def is_high_entropy(s: str, threshold: float = 3.5) -> bool:
    """Check if a string has high entropy (indicating randomness)."""
    if len(s) < 16:
        return False
    
    # Skip strings with too many zeroes (likely placeholders or test data)
    zero_count = s.count('0')
    if zero_count > len(s) * 0.4:  # If more than 40% of chars are zeros
        return False
    
    entropy = calculate_entropy(s)
    distribution_score = calculate_character_distribution_score(s)
    
    # Combined score that weighs both entropy and distribution
    combined_score = (entropy * 0.7) + (distribution_score * 2.0)
    
    return combined_score > threshold


def identify_provider_from_key(key: str) -> Optional[Provider]:
    """Try to identify the provider based on key format."""
    # Check for known prefixes first
    for prefix, provider in PROVIDER_PREFIXES.items():
        if key.startswith(prefix):
            if isinstance(provider, list):
                # For shared prefixes, check by length or other characteristics
                for potential_provider in provider:
                    pattern = PROVIDER_PATTERNS[potential_provider]
                    if pattern.fullmatch(key):
                        return potential_provider
            else:
                return provider
    
    # Check against all patterns for a full match
    for provider, pattern in PROVIDER_PATTERNS.items():
        if pattern.fullmatch(key):
            return provider
            
    return None


def get_context(text: str, match_start: int, match_end: int, context_size: int = 50) -> str:
    """Extract context around the match."""
    start = max(0, match_start - context_size)
    end = min(len(text), match_end + context_size)
    
    if start > 0:
        start_ellipsis = "..."
    else:
        start_ellipsis = ""
        
    if end < len(text):
        end_ellipsis = "..."
    else:
        end_ellipsis = ""
    
    prefix = text[start:match_start]
    match = text[match_start:match_end]
    suffix = text[match_end:end]
    
    return f"{start_ellipsis}{prefix}[{match}]{suffix}{end_ellipsis}"


def determine_confidence(provider: Provider, key: str) -> Confidence:
    """Determine confidence level based on pattern and entropy."""
    # High confidence for providers with distinctive formats
    distinctive_providers = [
        Provider.OPENAI, Provider.ANTHROPIC, Provider.GEMINI,
        Provider.HUGGINGFACE, Provider.REPLICATE, Provider.CLARIFAI,
        Provider.GROQ
    ]
    
    if provider in distinctive_providers:
        return Confidence.HIGH
    
    # For less distinctive formats, use entropy and other heuristics
    if provider == Provider.GENERIC:
        if is_high_entropy(key):
            # Additional checks for generic keys
            if re.search(r'(api|key|token|secret)', key, re.IGNORECASE):
                return Confidence.MEDIUM
            return Confidence.LOW
        return Confidence.LOW
    
    # For other providers with less distinctive patterns
    if is_high_entropy(key):
        return Confidence.MEDIUM
    return Confidence.LOW


def looks_like_key(text: str, line_number: Optional[int] = None, 
                  file_path: Optional[str] = None) -> Iterator[KeyFinding]:
    """Scan text for potential API keys."""
    for provider, pattern in PROVIDER_PATTERNS.items():
        for match in pattern.finditer(text):
            key = match.group(0)
            
            # Skip if key is likely a placeholder (too many zeroes)
            zero_count = key.count('0')
            if zero_count > len(key) * 0.4:  # If more than 40% of chars are zeros
                continue
                
            # Skip if key consists of repeating patterns
            if len(set(key)) < 8:  # Less than 8 unique characters
                continue
            
            # Try to identify a more specific provider if this is a generic match
            if provider == Provider.GENERIC:
                specific_provider = identify_provider_from_key(key)
                if specific_provider and specific_provider != Provider.GENERIC:
                    provider = specific_provider
            
            confidence = determine_confidence(provider, key)
            context = get_context(text, match.start(), match.end())
            
            yield KeyFinding(
                provider=provider,
                key=key,
                confidence=confidence,
                context=context,
                line_number=line_number,
                file_path=file_path,
                valid=None
            ) 