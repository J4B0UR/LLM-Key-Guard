"""Slack scanner to find API keys in message history."""

import os
from datetime import datetime, timedelta
from typing import Dict, Iterator, List, Optional, Tuple, Union

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from llm_key_guard.detectors import KeyFinding, looks_like_key


class SlackScanner:
    """Scan Slack message history for API keys."""
    
    def __init__(self, token: Optional[str] = None):
        """Initialize the Slack scanner.
        
        Args:
            token: Slack API token. If None, will try to read from SLACK_API_TOKEN env var.
        """
        self.token = token or os.environ.get("SLACK_API_TOKEN")
        if not self.token:
            raise ValueError(
                "Slack API token required. Set SLACK_API_TOKEN environment variable "
                "or pass token to SlackScanner constructor."
            )
        self.client = WebClient(token=self.token)
        
    def get_channel_id(self, channel_name: str) -> str:
        """Get channel ID from name."""
        # Remove leading # if present
        channel_name = channel_name.lstrip('#')
        
        # Try conversation list for public channels
        try:
            result = self.client.conversations_list()
            channels = result.get("channels", [])
            for channel in channels:
                if channel["name"] == channel_name:
                    return channel["id"]
                    
            # If not found in public channels, try private channels
            result = self.client.conversations_list(types="private_channel")
            channels = result.get("channels", [])
            for channel in channels:
                if channel["name"] == channel_name:
                    return channel["id"]
        except SlackApiError as e:
            raise RuntimeError(f"Error fetching channels: {str(e)}")
            
        raise ValueError(f"Channel '{channel_name}' not found")
        
    def scan_channel(
        self,
        channel: str,
        days_back: int = 30,
        limit: int = 1000,
        show_progress: bool = True
    ) -> Iterator[KeyFinding]:
        """Scan a Slack channel for API keys.
        
        Args:
            channel: Channel name (with or without #) or ID
            days_back: How many days back to scan
            limit: Maximum number of messages to scan
            show_progress: Whether to show a progress bar
            
        Yields:
            KeyFinding objects for each detected API key
        """
        # Get channel ID if name provided
        channel_id = channel if channel.startswith('C') and len(channel) == 11 else self.get_channel_id(channel)
        
        # Calculate oldest timestamp to fetch (days_back days ago)
        oldest = (datetime.now() - timedelta(days=days_back)).timestamp()
        
        # Fetch messages
        all_messages = []
        cursor = None
        
        while True:
            try:
                # Get history with pagination
                result = self.client.conversations_history(
                    channel=channel_id,
                    limit=100,  # API max
                    oldest=oldest,
                    cursor=cursor
                )
                
                messages = result.get("messages", [])
                all_messages.extend(messages)
                
                # Check if we've hit our message limit
                if len(all_messages) >= limit:
                    all_messages = all_messages[:limit]
                    break
                    
                # Get next page cursor
                cursor = result.get("response_metadata", {}).get("next_cursor")
                if not cursor or not result.get("has_more", False):
                    break
                    
            except SlackApiError as e:
                raise RuntimeError(f"Error fetching messages: {str(e)}")
                
        # Process messages
        progress = None
        task_id = None
        
        try:
            if show_progress and all_messages:
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeRemainingColumn()
                )
                progress.start()
                task_id = progress.add_task("[cyan]Scanning Slack messages[/cyan]", total=len(all_messages))
                
            for i, message in enumerate(all_messages):
                if show_progress and progress and task_id is not None:
                    progress.update(task_id, completed=i)
                    
                # Check message text
                text = message.get("text", "")
                user = message.get("user", "unknown")
                ts = message.get("ts", "0")
                
                # Convert timestamp to datetime
                dt = datetime.fromtimestamp(float(ts))
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                
                # Context to attach to findings
                context_info = f"Slack message from user {user} at {formatted_time}"
                
                # Scan message text
                for finding in looks_like_key(text):
                    # Add context about where this was found
                    finding.context = f"{context_info}: {finding.context}"
                    yield finding
                    
                # Also check attachments and files
                for attachment in message.get("attachments", []):
                    attachment_text = attachment.get("text", "")
                    for finding in looks_like_key(attachment_text):
                        finding.context = f"{context_info} (attachment): {finding.context}"
                        yield finding
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