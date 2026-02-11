"""
NumaSec Benchmark — Pytest Configuration

Docker/Podman container setup and teardown for DVWA and Juice Shop.
These benchmarks are SLOW (require container startup + full assessment).
Run separately with: pytest tests/benchmarks/ -v --benchmark
"""

from __future__ import annotations

import os
import subprocess
import time
import logging

import pytest
import httpx

logger = logging.getLogger("numasec.benchmark")

# Container runtime: prefer podman, fallback to docker
CONTAINER_RUNTIME = os.environ.get("CONTAINER_RUNTIME", "docker")

# Port configuration
DVWA_PORT = int(os.environ.get("DVWA_PORT", "8080"))
DVWA_URL = f"http://localhost:{DVWA_PORT}"
JUICE_SHOP_PORT = int(os.environ.get("JUICE_SHOP_PORT", "3000"))
JUICE_SHOP_URL = f"http://localhost:{JUICE_SHOP_PORT}"


def _container_cmd(*args: str) -> list[str]:
    """Build container command."""
    return [CONTAINER_RUNTIME, *args]


def _wait_for_http(url: str, timeout: int = 120, interval: int = 3) -> bool:
    """Wait until an HTTP endpoint is responsive."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.get(url, timeout=5, follow_redirects=True)
            if resp.status_code < 500:
                return True
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout):
            pass
        time.sleep(interval)
    return False


def _is_container_running(name: str) -> bool:
    """Check if a named container is running."""
    try:
        result = subprocess.run(
            _container_cmd("inspect", "-f", "{{.State.Running}}", name),
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() == "true"
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


@pytest.fixture(scope="session")
def dvwa_target():
    """Start DVWA container and return its URL.

    Automatically pulls the image if needed, starts the container,
    waits for HTTP readiness, and tears down after the session.
    """
    if _is_container_running("numasec-dvwa"):
        logger.info("DVWA container already running")
        yield DVWA_URL
        return

    logger.info("Starting DVWA container...")
    try:
        subprocess.run(
            _container_cmd(
                "run", "-d", "--name", "numasec-dvwa",
                "-p", f"{DVWA_PORT}:80",
                "-e", "MYSQL_ROOT_PASSWORD=dvwa",
                "vulnerables/web-dvwa",
            ),
            check=True, capture_output=True, text=True, timeout=60,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Could not start DVWA container: {e.stderr}")

    if not _wait_for_http(DVWA_URL):
        pytest.skip("DVWA container did not become ready in time")

    logger.info(f"DVWA ready at {DVWA_URL}")
    yield DVWA_URL

    # Teardown
    subprocess.run(
        _container_cmd("rm", "-f", "numasec-dvwa"),
        capture_output=True, timeout=30,
    )


@pytest.fixture(scope="session")
def juice_shop_target():
    """Start Juice Shop container and return its URL.

    Automatically pulls the image if needed, starts the container,
    waits for HTTP readiness, and tears down after the session.
    """
    if _is_container_running("numasec-juice-shop"):
        logger.info("Juice Shop container already running")
        yield JUICE_SHOP_URL
        return

    logger.info("Starting Juice Shop container...")
    try:
        subprocess.run(
            _container_cmd(
                "run", "-d", "--name", "numasec-juice-shop",
                "-p", f"{JUICE_SHOP_PORT}:3000",
                "bkimminich/juice-shop",
            ),
            check=True, capture_output=True, text=True, timeout=60,
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Could not start Juice Shop container: {e.stderr}")

    if not _wait_for_http(JUICE_SHOP_URL):
        pytest.skip("Juice Shop container did not become ready in time")

    logger.info(f"Juice Shop ready at {JUICE_SHOP_URL}")
    yield JUICE_SHOP_URL

    # Teardown
    subprocess.run(
        _container_cmd("rm", "-f", "numasec-juice-shop"),
        capture_output=True, timeout=30,
    )
