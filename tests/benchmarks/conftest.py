"""Benchmark test configuration."""

import os

import pytest


@pytest.fixture
def benchmark_config():
    """Default benchmark configuration."""
    return {
        "timeout_minutes": 30,
        "budget_usd": 5.0,
        "scope": "standard",
    }


@pytest.fixture
def allow_internal(monkeypatch):
    """Set SECMCP_ALLOW_INTERNAL for localhost testing."""
    monkeypatch.setenv("SECMCP_ALLOW_INTERNAL", "1")
