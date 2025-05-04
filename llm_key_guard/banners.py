"""ASCII Banners for LLM Key Guard CLI."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Main LLM Key Guard Banner
MAIN_BANNER = r"""
 __       __       __    __       __  __   ______   __  __   ______   __  __   ______   ______   _____      
/\ \     /\ \     /\ "-./  \     /\ \/ /  /\  ___\ /\ \_\ \ /\  ___\ /\ \/\ \ /\  __ \ /\  == \ /\  __-.    
\ \ \____\ \ \____\ \ \-./\ \    \ \  _"-.\ \  __\ \ \____ \\ \ \__ \\ \ \_\ \\ \  __ \\ \  __< \ \ \/\ \   
 \ \_____\\ \_____\\ \_\ \ \_\    \ \_\ \_\\ \_____\\/\_____\\ \_____\\ \_____\\ \_\ \_\\ \_\ \_\\ \____-   
  \/_____/ \/_____/ \/_/  \/_/     \/_/\/_/ \/_____/ \/_____/ \/_____/ \/_____/ \/_/\/_/ \/_/ /_/ \/____/   
                                                                                                            
   
"""

# Scan Banner
SCAN_BANNER = r"""

 ______   ______   ______   __   __   __   __   __   __   __   ______    
/\  ___\ /\  ___\ /\  __ \ /\ "-.\ \ /\ "-.\ \ /\ \ /\ "-.\ \ /\  ___\   
\ \___  \\ \ \____\ \  __ \\ \ \-.  \\ \ \-.  \\ \ \\ \ \-.  \\ \ \__ \  
 \/\_____\\ \_____\\ \_\ \_\\ \_\\"\_\\ \_\\"\_\\ \_\\ \_\\"\_\\ \_____\ 
  \/_____/ \/_____/ \/_/\/_/ \/_/ \/_/ \/_/ \/_/ \/_/ \/_/ \/_/ \/_____/ 
                                                                         
                
"""

# Git History Banner
GIT_HISTORY_BANNER = r"""

 ______   __   ______     __  __   __   ______   ______  ______   ______   __  __    
/\  ___\ /\ \ /\__  _\   /\ \_\ \ /\ \ /\  ___\ /\__  _\/\  __ \ /\  == \ /\ \_\ \   
\ \ \__ \\ \ \\/_/\ \/   \ \  __ \\ \ \\ \___  \\/_/\ \/\ \ \/\ \\ \  __< \ \____ \  
 \ \_____\\ \_\  \ \_\    \ \_\ \_\\ \_\\/\_____\  \ \_\ \ \_____\\ \_\ \_\\/\_____\ 
  \/_____/ \/_/   \/_/     \/_/\/_/ \/_/ \/_____/   \/_/  \/_____/ \/_/ /_/ \/_____/ 
                                                                                     
                                                                                  
"""

# Git Diff Banner
GIT_DIFF_BANNER = r"""

 ______   __   ______     _____    __   ______  ______  
/\  ___\ /\ \ /\__  _\   /\  __-. /\ \ /\  ___\/\  ___\ 
\ \ \__ \\ \ \\/_/\ \/   \ \ \/\ \\ \ \\ \  __\\ \  __\ 
 \ \_____\\ \_\  \ \_\    \ \____- \ \_\\ \_\   \ \_\   
  \/_____/ \/_/   \/_/     \/____/  \/_/ \/_/    \/_/   
                                                        

"""

# Help Banner
HELP_BANNER = r"""

 __  __   ______   __       ______  
/\ \_\ \ /\  ___\ /\ \     /\  == \ 
\ \  __ \\ \  __\ \ \ \____\ \  _-/ 
 \ \_\ \_\\ \_____\\ \_____\\ \_\   
  \/_/\/_/ \/_____/ \/_____/ \/_/   
                                    
   
"""

# Version Banner
VERSION_BANNER = r"""

 __   __ ______   ______   ______   __   ______   __   __    
/\ \ / //\  ___\ /\  == \ /\  ___\ /\ \ /\  __ \ /\ "-.\ \   
\ \ \'/ \ \  __\ \ \  __< \ \___  \\ \ \\ \ \/\ \\ \ \-.  \  
 \ \__|  \ \_____\\ \_\ \_\\/\_____\\ \_\\ \_____\\ \_\\"\_\ 
  \/_/    \/_____/ \/_/ /_/ \/_____/ \/_/ \/_____/ \/_/ \/_/ 
                                                             

"""

def print_main_banner(console: Console = None):
    """Print the main banner with info about the tool."""
    console = console or Console()
    
    # Create text with the banner in cyan color
    banner_text = Text(MAIN_BANNER, style="cyan bold")
    
    # Add description
    description = Text("\nA security tool to detect and validate API keys in your code and repositories", style="white")
    description.justify = "center"
    banner_text.append(description)
    
    # Add version info
    try:
        from llm_key_guard import __version__
        version_text = Text(f"\nv{__version__}", style="green")
        banner_text.append(version_text)
    except ImportError:
        pass
    
    # Add LinkedIn info
    linkedin_text = Text("\nBy: Gabriel Jabour | https://www.linkedin.com/in/gjabour/", style="blue underline")
    banner_text.append(linkedin_text)
    
    # Create panel
    panel = Panel(
        banner_text,
        expand=False,
        border_style="cyan",
        padding=(1, 2)
    )
    
    # Print the panel
    console.print(panel)

def print_command_banner(command: str, console: Console = None):
    """Print a banner for a specific command."""
    console = console or Console()
    
    # Select the appropriate banner
    if command == "scan":
        banner = SCAN_BANNER
        title = "Scan for API Keys"
    elif command == "git-history":
        banner = GIT_HISTORY_BANNER
        title = "Git History Scanner"
    elif command == "git-diff":
        banner = GIT_DIFF_BANNER
        title = "Git Diff Scanner"
    elif command == "help":
        banner = HELP_BANNER
        title = "Help Information"
    elif command == "version":
        banner = VERSION_BANNER
        title = "Version Information"
    else:
        return
    
    # Create text with the banner
    banner_text = Text(banner, style="cyan bold")
    
    # Create panel
    panel = Panel(
        banner_text,
        title=title,
        expand=False,
        border_style="cyan",
        padding=(1, 2)
    )
    
    # Print the panel
    console.print(panel) 