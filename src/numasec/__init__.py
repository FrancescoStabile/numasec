"""NumaSec v3 — AI-powered autonomous pentesting agent."""

__version__ = "3.0.0"
__author__ = "Francesco Stabile"
__description__ = "AI-powered autonomous pentesting agent with SOTA prompt engineering"

# Export key components
from numasec.config import load_config, ensure_config, Config

__all__ = ["load_config", "ensure_config", "Config"]
