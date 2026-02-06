"""
NumaSec Config Management

Unified configuration loading from multiple sources:
1. ~/.numasec/config.yaml (persistent, recommended)
2. .env file (project-local)
3. Environment variables (override)

Priority: ENV > .env > config.yaml
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# ═══════════════════════════════════════════════════════════════════════════
# Config Paths
# ═══════════════════════════════════════════════════════════════════════════

NUMASEC_HOME = Path.home() / ".numasec"
CONFIG_FILE = NUMASEC_HOME / "config.yaml"
SESSIONS_DIR = NUMASEC_HOME / "sessions"


# ═══════════════════════════════════════════════════════════════════════════
# Config Loader
# ═══════════════════════════════════════════════════════════════════════════


class Config:
    """Unified configuration management."""
    
    def __init__(self):
        self.data: dict[str, Any] = {}
        self._load()
    
    def _load(self):
        """Load config from all sources (priority: ENV > .env > config.yaml)."""
        # 1. Load from ~/.numasec/config.yaml
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE) as f:
                self.data = yaml.safe_load(f) or {}
        
        # 2. Load from .env file (project-local)
        self._load_dotenv()
        
        # 3. Environment variables override everything
        self._apply_env_overrides()
    
    def _load_dotenv(self):
        """Load .env file from cwd or parent directories."""
        check = Path.cwd()
        for _ in range(5):  # Check up to 5 parent directories
            env_file = check / ".env"
            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        
                        # Only set if not already in config
                        if key not in os.environ:
                            self.data.setdefault(key, value)
                
                return
            check = check.parent
    
    def _apply_env_overrides(self):
        """Environment variables override config file."""
        for key in ["DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"]:
            if key in os.environ:
                self.data[key] = os.environ[key]
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get config value."""
        return self.data.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set config value (in-memory only)."""
        self.data[key] = value
    
    def save(self):
        """Save config to ~/.numasec/config.yaml."""
        try:
            NUMASEC_HOME.mkdir(parents=True, exist_ok=True)
            
            with open(CONFIG_FILE, "w") as f:
                yaml.dump(self.data, f, default_flow_style=False)
        except (OSError, PermissionError) as e:
            # Can't save config (e.g., container permission issues)
            # Config will only be in-memory, but that's OK for this session
            import sys
            print(f"[!] Warning: Could not save config to {CONFIG_FILE}: {e}", file=sys.stderr)
            print(f"[i] Config will work for this session only.", file=sys.stderr)
            print(f"[i] To persist, set environment variables or use .env file.", file=sys.stderr)
    
    def has_api_key(self) -> bool:
        """Check if at least one API key is configured."""
        return any([
            self.get("DEEPSEEK_API_KEY"),
            self.get("ANTHROPIC_API_KEY"),
            self.get("OPENAI_API_KEY"),
        ])
    
    def get_api_keys(self) -> dict[str, str]:
        """Get all configured API keys."""
        keys = {}
        for key in ["DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"]:
            value = self.get(key)
            if value:
                keys[key] = value
        return keys


# ═══════════════════════════════════════════════════════════════════════════
# Interactive Setup
# ═══════════════════════════════════════════════════════════════════════════


def interactive_setup() -> Config:
    """Interactive first-time setup."""
    from rich.console import Console
    from rich.prompt import Prompt
    
    console = Console()
    config = Config()
    
    console.print("\n[bold cyan]NumaSec Configuration[/]")
    console.print("Let's set up your API keys. You need at least one.\n")
    
    console.print("[bold green]DeepSeek[/] (Recommended - $0.12/pentest avg)")
    console.print("Get key: https://platform.deepseek.com\n")
    deepseek_key = Prompt.ask(
        "DeepSeek API Key",
        default=config.get("DEEPSEEK_API_KEY", ""),
        password=True,
    )
    if deepseek_key:
        config.set("DEEPSEEK_API_KEY", deepseek_key)
    
    console.print("\n[bold yellow]Anthropic Claude[/] (Fallback)")
    console.print("Get key: https://console.anthropic.com\n")
    claude_key = Prompt.ask(
        "Claude API Key (optional)",
        default=config.get("ANTHROPIC_API_KEY", ""),
        password=True,
    )
    if claude_key:
        config.set("ANTHROPIC_API_KEY", claude_key)
    
    console.print("\n[bold blue]OpenAI GPT-4[/] (Fallback)")
    console.print("Get key: https://platform.openai.com\n")
    openai_key = Prompt.ask(
        "OpenAI API Key (optional)",
        default=config.get("OPENAI_API_KEY", ""),
        password=True,
    )
    if openai_key:
        config.set("OPENAI_API_KEY", openai_key)
    
    if not config.has_api_key():
        console.print("\n[bold red][!] No API keys configured![/]")
        console.print("You need at least one API key to use NumaSec.\n")
        return config
    
    # Save config (may fail in container, that's OK)
    config.save()
    
    # Check if save was successful
    if CONFIG_FILE.exists():
        console.print(f"\n[bold green][+] Config saved to:[/] {CONFIG_FILE}")
        console.print("\nYou can edit it anytime: [cyan]~/.numasec/config.yaml[/]\n")
    else:
        console.print(f"\n[bold yellow][+] Config loaded (session-only)[/]")
        console.print("Note: Could not save to disk (container permissions).")
        console.print("Use environment variables for persistent config.\n")
    
    return config


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════


def load_config() -> Config:
    """Load config from all sources."""
    return Config()


def ensure_config() -> Config:
    """Ensure config exists, run interactive setup if needed."""
    config = Config()
    
    # If API keys are already available (from ENV or config file), don't prompt
    if config.has_api_key():
        return config
    
    # No API keys found, run interactive setup
    config = interactive_setup()
    
    return config
