"""Filesystem scanner to find API keys in local files."""

import os
import pathlib
import concurrent.futures
import json
import hashlib
import time
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union, Generator

import git
from tqdm import tqdm
import fnmatch
import glob
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import gitignore_parser
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from llm_key_guard.detectors import (
    Confidence,
    KeyFinding,
    Provider,
    looks_like_key,
)
from llm_key_guard.detectors.patterns import PROVIDER_PATTERNS


class FileCache:
    """Cache system for file scanning to avoid rescanning unmodified files."""
    
    def __init__(self, cache_file: str = ".llm_key_guard_cache.json"):
        """Initialize the file cache.
        
        Args:
            cache_file: Path to the cache file
        """
        self.cache_file = cache_file
        self.cache = self._load_cache()
    
    def _load_cache(self) -> Dict:
        """Load cache from disk."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {'files': {}, 'version': 1}
        return {'files': {}, 'version': 1}
    
    def _save_cache(self) -> None:
        """Save cache to disk."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except IOError:
            # If we can't save the cache, just continue without it
            pass
    
    def _get_file_hash(self, file_path: str) -> str:
        """Calculate a hash of file contents."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except IOError:
            # If we can't read the file, return a unique hash
            return f"error-{int(time.time())}"
    
    def get_file_info(self, file_path: str) -> Tuple[str, int]:
        """Get file hash and modification time."""
        file_hash = self._get_file_hash(file_path)
        mod_time = int(os.path.getmtime(file_path))
        return file_hash, mod_time
    
    def is_cached(self, file_path: str) -> bool:
        """Check if a file is in the cache and unchanged."""
        if file_path not in self.cache['files']:
            return False
        
        cached_info = self.cache['files'][file_path]
        current_hash, current_mtime = self.get_file_info(file_path)
        
        # Check if hash and modification time match
        return (cached_info['hash'] == current_hash and 
                cached_info['mtime'] == current_mtime)
    
    def get_cached_findings(self, file_path: str) -> List[Dict]:
        """Get cached findings for a file."""
        if not self.is_cached(file_path):
            return []
        
        return self.cache['files'][file_path]['findings']
    
    def update_cache(self, file_path: str, findings: List[KeyFinding]) -> None:
        """Update cache with new findings."""
        # Convert KeyFindings to serializable dictionaries
        serialized_findings = []
        for finding in findings:
            serialized = {
                'provider': finding.provider.value,
                'key_prefix': finding.key[:8],  # Store only prefix for security
                'confidence': str(finding.confidence),
                'line_number': finding.line_number,
                'context': finding.context
            }
            serialized_findings.append(serialized)
        
        # Update cache entry
        file_hash, mod_time = self.get_file_info(file_path)
        self.cache['files'][file_path] = {
            'hash': file_hash,
            'mtime': mod_time,
            'findings': serialized_findings,
            'last_scan': int(time.time())
        }
        
        # Save cache to disk
        self._save_cache()


def _scan_file(file_path: str) -> List[KeyFinding]:
    """Scan a single file for API keys.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of KeyFinding objects
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return list(scan_content(file_path, content))
    except Exception:
        # Return empty list if file can't be read
        return []


def is_binary_file(file_path: str) -> bool:
    """Check if a file is binary.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file is binary, False otherwise
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except Exception:
        # If we can't open the file, assume it's not binary
        return False


def is_git_ignored(repo_path: str, file_path: str) -> bool:
    """Check if a file is git ignored."""
    try:
        repo = git.Repo(repo_path)
        rel_path = os.path.relpath(file_path, repo.working_dir)
        return rel_path in repo.git.execute(['git', 'check-ignore', '--no-index', rel_path])
    except (git.InvalidGitRepositoryError, git.NoSuchPathError):
        return False


def get_file_extension(file_path: str) -> str:
    """Get file extension from path."""
    return os.path.splitext(file_path)[1].lower()


def should_scan_file(file_path: str, 
                    ignore_git: bool = True, 
                    repo_path: Optional[str] = None,
                    exclude_extensions: Optional[Set[str]] = None) -> bool:
    """Determine if a file should be scanned."""
    if exclude_extensions is None:
        exclude_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.flv', '.wmv',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.pyc', '.pyo', '.pyd',
            '.so', '.dll', '.exe',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.lock', '.min.js', '.min.css',  # Added common minified files
            '.ttf', '.woff', '.woff2', '.eot',  # Fonts
            '.svg'  # Vector graphics
        }
    
    # Skip hidden files and directories
    if os.path.basename(file_path).startswith('.'):
        return False
    
    # Skip binary and excluded extensions
    if is_binary_file(file_path) or get_file_extension(file_path) in exclude_extensions:
        return False
    
    # Skip git ignored files if requested
    if ignore_git and repo_path and is_git_ignored(repo_path, file_path):
        return False
    
    # Skip files that are too large (> 10MB)
    try:
        if os.path.getsize(file_path) > 10 * 1024 * 1024:
            return False
    except (IOError, OSError):
        pass
    
    return True


def scan_file(file_path: str) -> Iterator[KeyFinding]:
    """Scan a single file for API keys."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                for finding in looks_like_key(line, line_number=i, file_path=file_path):
                    yield finding
    except (UnicodeDecodeError, IOError):
        # Skip files that can't be read
        pass


def scan_directory(
    directory: str,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    respect_gitignore: bool = True,
    show_progress: bool = True,
    threads: int = 1,
    progress: Optional[Progress] = None
) -> Generator[KeyFinding, None, None]:
    """Scan directory recursively for API keys.
    
    Args:
        directory: Directory to scan
        include_patterns: Glob patterns of files to include
        exclude_patterns: Glob patterns of files to exclude
        respect_gitignore: Whether to respect .gitignore files
        show_progress: Whether to show progress bar
        threads: Number of threads to use for scanning
        progress: Optional Progress instance to reuse
        
    Yields:
        KeyFinding objects for each key found
    """
    # Get matching files
    all_files = get_files_to_scan(
        directory, 
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        respect_gitignore=respect_gitignore,
        show_progress=show_progress,
        progress=progress
    )
    
    total_files = len(all_files)
    
    if total_files == 0:
        return
        
    # Set up progress tracking
    should_create_progress = show_progress and progress is None
    should_close_progress = should_create_progress
    
    if should_create_progress:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn()
        )
        progress.start()
        
    try:
        task_id = progress.add_task("[cyan]Scanning files[/cyan]", total=total_files) if progress else None
            
        if threads > 1:
            # Multi-threaded scanning
            with ThreadPoolExecutor(max_workers=threads) as executor:
                # Map file paths to futures
                futures = []
                for file_path in all_files:
                    futures.append(executor.submit(_scan_file, file_path))
                    
                # Process results as they complete
                for i, future in enumerate(futures):
                    if show_progress and progress and task_id is not None:
                        progress.update(task_id, completed=i+1)
                        
                    findings = future.result()
                    if findings:
                        for finding in findings:
                            yield finding
        else:
            # Single-threaded scanning
            for i, file_path in enumerate(all_files):
                if show_progress and progress and task_id is not None:
                    progress.update(task_id, completed=i+1)
                    
                for finding in _scan_file(file_path):
                    yield finding
    finally:
        if progress and should_close_progress:
            progress.stop()


def get_files_to_scan(
    directory: str,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    respect_gitignore: bool = True,
    show_progress: bool = True,
    progress: Optional[Progress] = None
) -> List[str]:
    """Get list of files to scan based on patterns.
    
    Args:
        directory: Directory to scan
        include_patterns: Glob patterns of files to include
        exclude_patterns: Glob patterns of files to exclude
        respect_gitignore: Whether to respect .gitignore files
        show_progress: Whether to show progress bar
        progress: Optional Progress instance to reuse
        
    Returns:
        List of file paths to scan
    """
    # Get gitignore matcher if requested
    gitignore_matcher = None
    if respect_gitignore:
        gitignore_path = os.path.join(directory, ".gitignore")
        if os.path.isfile(gitignore_path):
            try:
                gitignore_matcher = gitignore_parser.parse_gitignore(gitignore_path)
            except Exception:
                # Fall back to no gitignore if parsing fails
                pass
                
    # Collect all files recursively
    all_files = []
    filtered_files = []
    
    should_create_progress = show_progress and progress is None
    should_close_progress = should_create_progress
    
    if should_create_progress:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TimeRemainingColumn()
        )
        progress.start()
        
    try:
        task_id = progress.add_task("[cyan]Collecting files[/cyan]") if progress else None
            
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)
                
                if progress and task_id is not None:
                    progress.update(task_id, description=f"[cyan]Collecting files[/cyan]: {len(all_files)} found")
                    
        # Update total if we're showing progress
        if progress and task_id is not None:
            progress.update(task_id, total=len(all_files), completed=0)
            progress.update(task_id, description=f"[cyan]Filtering files[/cyan]")
            
        # Apply filters
        for i, file_path in enumerate(all_files):
            if progress and task_id is not None:
                progress.update(task_id, completed=i)
                    
            # Skip binary files
            if is_binary_file(file_path):
                continue
                
            # Check gitignore
            if gitignore_matcher and gitignore_matcher(file_path):
                continue
                
            # Skip files not matching include patterns
            if include_patterns:
                rel_path = os.path.relpath(file_path, directory)
                if not any(fnmatch.fnmatch(rel_path, pattern) for pattern in include_patterns):
                    continue
                    
            # Skip files matching exclude patterns
            if exclude_patterns:
                rel_path = os.path.relpath(file_path, directory)
                if any(fnmatch.fnmatch(rel_path, pattern) for pattern in exclude_patterns):
                    continue
                    
            filtered_files.append(file_path)
        
        return filtered_files
    finally:
        if progress and should_close_progress:
            progress.stop()


def scan_content(file_path: str, content: str) -> Iterator[KeyFinding]:
    """Scan content string for API keys.
    
    Args:
        file_path: Path to the file (for reporting)
        content: String content to scan
        
    Yields:
        KeyFinding objects for each key found
    """
    # Debug output
    with open("scan_debug.log", "a") as debug_file:
        debug_file.write(f"\nScanning file: {file_path}\n")
        debug_file.write(f"Content length: {len(content)}\n")
        debug_file.write(f"First 100 chars: {repr(content[:100])}\n")
        debug_file.write(f"Contains 'sk-admin-': {'sk-admin-' in content}\n")
        
        # Try to detect key patterns manually
        for provider_name, pattern in PROVIDER_PATTERNS.items():
            matches = list(pattern.finditer(content))
            debug_file.write(f"Matches for {provider_name.value}: {len(matches)}\n")
            for i, match in enumerate(matches):
                debug_file.write(f"  Match {i+1}: {match.group(0)[:20]}...\n")
    
    # Skip content that looks like it contains test/placeholder data
    lower_content = content.lower()
    test_indicators = [
        "test key", "fake key", "example key", "placeholder", 
        "00000000", "11111111", "xxxxxxxx", "your_key_here",
        "your-api-key", "your-secret-key", "invalid-key"
    ]
    
    # Check if this is clearly test/example content
    if any(indicator in lower_content for indicator in test_indicators):
        # Still scan, but we'll be more strict with pattern matching
        strict_scan = True
    else:
        strict_scan = False
    
    # First pass - look for special API key formats that should never be ignored
    # (sk-admin-, sk-proj-, etc.)
    special_key_patterns = ["sk-admin-", "sk-proj-"]
    
    for i, line in enumerate(content.splitlines(), 1):
        # Always scan for special keys, regardless of whether it's a test file
        if any(pattern in line for pattern in special_key_patterns):
            for finding in looks_like_key(line, line_number=i, file_path=file_path):
                yield finding
    
    # Second pass - standard scanning with stricter rules for test files
    for i, line in enumerate(content.splitlines(), 1):
        # Skip if we already found a special key on this line
        if any(pattern in line for pattern in special_key_patterns):
            continue
            
        # Skip lines that are likely comments or placeholders in test files
        stripped = line.strip()
        if strict_scan and (
            stripped.startswith('#') or 
            stripped.startswith('//') or
            stripped.startswith('/*') or
            "example" in stripped.lower() or
            "placeholder" in stripped.lower()
        ):
            continue
            
        for finding in looks_like_key(line, line_number=i, file_path=file_path):
            yield finding 