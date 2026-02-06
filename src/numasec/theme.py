"""
Cyberpunk Theme System for NumaSec
========================================
Dark Mode + Neon aesthetics (Matrix/Mr. Robot vibes)
SOTA 2026: Minimalist, Ephemeral, Nerd Font Integrated
"""

from typing import Literal
from rich.console import Console
from rich.theme import Theme
from rich.text import Text
from rich.style import Style

# ═══════════════════════════════════════════════════════════════════════════
# MATRIX COLOR PALETTE (2026 HACKER EDITION)
# ═══════════════════════════════════════════════════════════════════════════

# Primary Matrix Green (dominant)
MATRIX_GREEN = "#00ff41"  # Brighter, more aggressive
NEON_GREEN = "#39ff14"    # Screaming neon

# Accent colors
CYBER_PURPLE = "#b968ff"  # More electric
HACK_RED = "#ff0051"      # Aggressive warning
ELECTRIC_CYAN = "#00ffff" # Pure cyan

# System colors
DARK_BG = "#000000"       # Pure black
DIM_GRAY = "#b0b0b0"      # Light gray (highly readable)
GHOST_GRAY = "#888888"    # Secondary text (readable on black)
GOLD = "#ffd700"          # Bright gold

# Legacy aliases for compatibility
WARNING_RED = HACK_RED
ELECTRIC_BLUE = ELECTRIC_CYAN
MUTED_TEXT = DIM_GRAY

# Create custom theme for Rich (MATRIX EDITION)
CYBERPUNK_THEME = Theme({
    "info": f"bold {MATRIX_GREEN}",
    "warning": f"bold {HACK_RED}",
    "error": f"bold {HACK_RED} blink",
    "success": f"bold {NEON_GREEN}",
    "breach": f"bold {CYBER_PURPLE}",  # For scanning/breaching
    "tool": f"bold {ELECTRIC_CYAN}",
    "dim": f"{GHOST_GRAY}",
    "prompt": f"bold {MATRIX_GREEN}",
    "agent": f"bold {MATRIX_GREEN}",
    "muted": f"{GHOST_GRAY}",
    "highlight": f"bold {GOLD}",
    "glitch": f"bold {HACK_RED} reverse",  # Glitch effect
})


class CyberpunkAssets:
    """MATRIX VISUAL ARSENAL - Hacker Elite Edition"""
    
    # Header
    BANNER_SMALL = f"[{MATRIX_GREEN}]NumaSec[/] [{GHOST_GRAY}]v3.0[/]"
    
    # Matrix Banner (ASCII Art)
    MATRIX_BANNER = f"""[{MATRIX_GREEN}]
███╗   ██╗██╗   ██╗███╗   ███╗ █████╗ ███████╗███████╗ ██████╗
████╗  ██║██║   ██║████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝
██╔██╗ ██║██║   ██║██╔████╔██║███████║███████╗█████╗  ██║     
██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██║╚════██║██╔══╝  ██║     
██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║███████║███████╗╚██████╗
╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
[/][{CYBER_PURPLE}]           The Neural Penetration Framework[/]
[{GHOST_GRAY}]                    v3.0.0 | 2026[/]
"""
    
    # Matrix rain characters
    MATRIX_CHARS = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
    
    # Tree symbols
    TREE_BRANCH = "├──"
    TREE_LAST = "└──"
    TREE_PIPE = "│  "
    TREE_SPACE = "   "
    
    # Icons - Hacker Style (pure ASCII, no emojis)
    ICON_BREACH = ">>"     # Breaching/scanning
    ICON_EXEC = "=>"       # Executing
    ICON_SUCCESS = "[+]"   # Success
    ICON_ERROR = "[X]"     # Error
    ICON_WARN = "[!]"      # Warning
    ICON_INFO = "[i]"      # Info
    ICON_LOCK = "[#]"      # Locked
    ICON_KEY = "[@]"       # Key/access
    ICON_VULN = "[!!]"     # Vulnerability found
    ICON_SCAN = "[~]"      # Scanning
    ICON_CRIT = "[!!!]"    # Critical
    ICON_TARGET = "[*]"    # Target acquired
    
    # Spinner Frames - Aggressive glitch style
    SPINNER_BREACH = ["[>  ]", "[>> ]", "[>>>]", "[>>>]", "[>>>]"]  # Breaching
    SPINNER_SCAN = ["[/]", "[-]", "[\\]", "[|]"]  # Scanning
    SPINNER_GLITCH = ["█", "▓", "▒", "░", "▒", "▓"]  # Glitch effect
    SPINNER_MATRIX = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]  # Matrix rain
    
    # Rich spinner names
    SPINNER_DOTS = "dots12"  # Faster dots
    
    @staticmethod
    def get_status_style(status: str) -> str:
        if status == "running": return ELECTRIC_CYAN
        if status == "success": return MATRIX_GREEN
        if status == "error": return HACK_RED
        return GHOST_GRAY

    @staticmethod
    def format_latency(ms: float) -> str:
        """Format latency with aggressive color coding"""
        if ms < 500:
            return f"[{MATRIX_GREEN}]{ms:.0f}ms[/]"
        elif ms < 2000:
            return f"[{GOLD}]{ms:.0f}ms[/]"
        else:
            return f"[{HACK_RED}]{ms:.0f}ms [!][/]"
