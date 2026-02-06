"""
Structured Logging for NumaSec - Phase 5 Hardening

JSON logging to file with rotation.
Helps debug production issues without cluttering user output.
"""

import logging
import logging.handlers
import json
from pathlib import Path
from typing import Any
import sys


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for machine parsing."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "tool_name"):
            log_data["tool_name"] = record.tool_name
        if hasattr(record, "provider"):
            log_data["provider"] = record.provider
        if hasattr(record, "cost"):
            log_data["cost"] = record.cost
        
        return json.dumps(log_data)


def setup_logging(verbose: bool = False):
    """
    Setup structured logging for NumaSec.
    
    Args:
        verbose: If True, also log to console (for --verbose flag)
    
    Returns:
        Logger instance
    """
    # Create logs directory
    log_dir = Path.home() / ".numasec" / "logs"
    
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError) as e:
        # If we can't create logs dir, log to stderr only
        root_logger = logging.getLogger("numasec")
        root_logger.setLevel(logging.WARNING if not verbose else logging.INFO)
        
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        root_logger.addHandler(console_handler)
        
        if verbose:
            root_logger.warning(f"Could not create log directory: {e}")
        
        return root_logger
    
    log_file = log_dir / "numasec.log"
    
    # Root logger
    root_logger = logging.getLogger("numasec")
    root_logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # File handler with rotation (10MB max, keep last 5 files)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)
    except (OSError, PermissionError) as e:
        # Fall back to stderr only
        if verbose:
            print(f"Warning: Could not create log file: {e}", file=sys.stderr)
    
    # Console handler (only if verbose)
    if verbose:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            "[%(levelname)s] %(name)s: %(message)s"
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # Log startup
    root_logger.info("NumaSec logging initialized", extra={"verbose": verbose})
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a specific module."""
    return logging.getLogger(f"numasec.{name}")
