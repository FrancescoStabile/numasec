"""NumaSec — AI security testing for your apps."""

__version__ = "3.0.0"
__author__ = "Francesco Stabile"
__description__ = "AI security testing for apps. Paste a URL, get a security report."

# Export key components
from numasec.config import load_config, ensure_config, Config

__all__ = ["load_config", "ensure_config", "Config"]
