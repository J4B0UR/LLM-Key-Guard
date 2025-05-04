"""Git history scanner to find API keys in historical commits."""

import os
import tempfile
from typing import Dict, Iterator, List, Optional, Set, Tuple

import git
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from tqdm import tqdm

from llm_key_guard.detectors import KeyFinding, looks_like_key
from llm_key_guard.scanner.filesystem import should_scan_file


def scan_git_history(
    repo_path: Optional[str] = None,
    max_commits: Optional[int] = None,
    branch: str = "HEAD",
    show_progress: bool = True,
    exclude_extensions: Optional[Set[str]] = None
) -> Iterator[KeyFinding]:
    """Scan Git commit history for API keys.
    
    Args:
        repo_path: Path to Git repository. If None, uses current directory.
        max_commits: Maximum number of commits to scan. If None, scan all.
        branch: Git branch to scan. Defaults to HEAD.
        show_progress: Whether to show a progress bar.
        exclude_extensions: File extensions to exclude
        
    Yields:
        KeyFinding objects for each key found
    """
    if not repo_path:
        repo_path = os.getcwd()
        
    try:
        repo = git.Repo(repo_path)
    except git.InvalidGitRepositoryError:
        raise ValueError(f"Not a valid Git repository: {repo_path}")
        
    # Get all commits for the branch
    commits = list(repo.iter_commits(branch))
    
    # Only use the first max_commits if specified
    if max_commits and max_commits > 0:
        commits = commits[:max_commits]
        
    # Use progress bar if requested
    progress = None
    task_id = None
    
    try:
        if show_progress:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn()
            )
            progress.start()
            task_id = progress.add_task("[cyan]Scanning git history[/cyan]", total=len(commits))
        
        # Track already seen files to avoid duplicate scanning
        seen_blobs = set()
        processed_commits = 0
        
        # Create a temporary directory for extracting files
        with tempfile.TemporaryDirectory() as temp_dir:
            for i, commit in enumerate(commits):
                processed_commits += 1
                
                if show_progress and progress and task_id is not None:
                    progress.update(task_id, completed=i)
                
                # Skip merge commits (they don't have unique content)
                if len(commit.parents) > 1:
                    continue
                
                # Get the commit diff
                if commit.parents:
                    diffs = commit.parents[0].diff(commit)
                else:
                    # First commit - get all files
                    diffs = commit.diff(git.NULL_TREE)
                
                for diff in diffs:
                    # Skip if deleted file or not a blob
                    if diff.deleted_file or not diff.b_blob:
                        continue
                    
                    # Skip if we've already seen this exact blob
                    if diff.b_blob.hexsha in seen_blobs:
                        continue
                    
                    seen_blobs.add(diff.b_blob.hexsha)
                    
                    # Get file path and check if it should be scanned
                    file_path = os.path.join(repo_path, diff.b_path)
                    if not should_scan_file(file_path, False, None, exclude_extensions):
                        continue
                    
                    # Get file content and scan it
                    try:
                        # Extract file content to a temporary file to avoid memory issues with large files
                        temp_file_path = os.path.join(temp_dir, os.path.basename(diff.b_path))
                        with open(temp_file_path, 'wb') as f:
                            diff.b_blob.stream_data(f)
                        
                        # Scan the temporary file
                        with open(temp_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for i, line in enumerate(f, 1):
                                for finding in looks_like_key(
                                    line,
                                    line_number=i,
                                    file_path=diff.b_path  # Use the relative path in the repo
                                ):
                                    # Enrich with git metadata
                                    finding.context = f"[Git commit {commit.hexsha[:8]}] {finding.context}"
                                    # Save as historical finding
                                    finding.file_path = f"[Historical] {finding.file_path}"
                                    yield finding
                                    
                    except (UnicodeDecodeError, IOError):
                        # Skip files that can't be read
                        continue
    finally:
        if progress:
            progress.stop()


def scan_git_branch_comparison(
    repo_path: str,
    base_branch: str = "main",
    compare_branch: str = "HEAD",
    show_progress: bool = True,
    exclude_extensions: Optional[Set[str]] = None
) -> Iterator[KeyFinding]:
    """Scan git branch comparison for API keys.
    
    Useful for CI/CD to scan only changes between branches (e.g., in a PR).
    
    Args:
        repo_path: Path to the Git repository
        base_branch: Base branch for comparison (e.g., main)
        compare_branch: Branch to compare against base (e.g., feature branch)
        show_progress: Whether to show a progress bar
        exclude_extensions: File extensions to exclude
        
    Yields:
        KeyFinding objects for each detected API key
    """
    try:
        repo = git.Repo(repo_path)
    except git.InvalidGitRepositoryError:
        raise ValueError(f"Not a valid git repository: {repo_path}")
    
    # Get the merge base (common ancestor)
    try:
        base_commit = repo.merge_base(base_branch, compare_branch)[0]
    except (IndexError, git.GitCommandError):
        raise ValueError(f"Could not find common ancestor between {base_branch} and {compare_branch}")
    
    # Get the diff between the base and compare branches
    diffs = repo.git.diff(base_commit.hexsha, compare_branch, name_only=True).split('\n')
    
    # Filter out empty strings
    diffs = [diff for diff in diffs if diff]
    
    # Set up progress bar if requested
    files_iterator = tqdm(diffs, desc="Scanning branch diff") if show_progress else diffs
    
    # Create a temporary directory for extracting files
    with tempfile.TemporaryDirectory() as temp_dir:
        for file_path in files_iterator:
            # Get the full path and check if it should be scanned
            full_path = os.path.join(repo_path, file_path)
            if not os.path.exists(full_path) or not should_scan_file(full_path, False, None, exclude_extensions):
                continue
            
            # Get the file content from the compare branch
            try:
                # Get file content from Git and write to temp file
                file_content = repo.git.show(f"{compare_branch}:{file_path}")
                temp_file_path = os.path.join(temp_dir, os.path.basename(file_path))
                
                with open(temp_file_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(file_content)
                
                # Scan the temporary file
                with open(temp_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        for finding in looks_like_key(line, line_number=i, file_path=file_path):
                            # Mark as part of the branch comparison
                            finding.context = f"[Branch diff {base_branch}..{compare_branch}] {finding.context}"
                            yield finding
                            
            except (UnicodeDecodeError, IOError, git.GitCommandError):
                # Skip files that can't be read or aren't in the branch
                continue 

def scan_git_diff(
    repo_path: Optional[str] = None,
    base: str = "main",
    compare: str = "HEAD",
    show_progress: bool = True,
    exclude_extensions: Optional[Set[str]] = None
) -> Iterator[KeyFinding]:
    """Scan differences between Git branches for API keys.
    
    Args:
        repo_path: Path to Git repository. If None, uses current directory.
        base: Base branch to compare against.
        compare: Branch to compare with base.
        show_progress: Whether to show a progress bar.
        exclude_extensions: File extensions to exclude
        
    Yields:
        KeyFinding objects for each key found
    """
    if not repo_path:
        repo_path = os.getcwd()
        
    try:
        repo = git.Repo(repo_path)
    except git.InvalidGitRepositoryError:
        raise ValueError(f"Not a valid Git repository: {repo_path}")
        
    # Get the diff between branches
    try:
        diffs = repo.git.diff(f"{base}...{compare}", name_only=True).splitlines()
    except git.GitCommandError as e:
        raise ValueError(f"Failed to get diff between {base} and {compare}: {e}")
        
    if not diffs:
        return
    
    # Use progress bar if requested
    progress = None
    task_id = None
    
    try:
        if show_progress:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn()
            )
            progress.start()
            task_id = progress.add_task("[cyan]Scanning branch diff[/cyan]", total=len(diffs))
        
        # Process each changed file
        for i, file_path in enumerate(diffs):
            if show_progress and progress and task_id is not None:
                progress.update(task_id, completed=i)
                
            # Skip files with excluded extensions
            if exclude_extensions and any(file_path.endswith(ext) for ext in exclude_extensions):
                continue
                
            try:
                file_content = repo.git.show(f"{compare}:{file_path}")
                for finding in scan_content(file_path, file_content):
                    yield finding
            except git.GitCommandError:
                # File might have been deleted in compare
                continue
    finally:
        if progress:
            progress.stop()

def scan_content(file_path: str, content: str) -> Iterator[KeyFinding]:
    """Scan file content for API keys.
    
    Args:
        file_path: Path to the file (or identifier for non-file sources)
        content: Text content to scan
        
    Yields:
        KeyFinding objects for each key found
    """
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        for finding in looks_like_key(line, line_number=i, file_path=file_path):
            yield finding 