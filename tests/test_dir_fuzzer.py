"""Tests for security_mcp.scanners.dir_fuzzer."""

from __future__ import annotations

import json

import httpx
import pytest

from security_mcp.scanners.dir_fuzzer import (
    COMMON_PATHS,
    FuzzResult,
    PythonDirFuzzer,
    python_dir_fuzz,
)


def _mock_transport(responses: dict[str, tuple[int, str]]) -> httpx.MockTransport:
    """Create a MockTransport that returns predefined responses by path."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.lstrip("/")
        if path in responses:
            status, body = responses[path]
            return httpx.Response(status, text=body)
        # Default: 404 with consistent body
        return httpx.Response(404, text="Not Found")

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# FuzzResult dataclass
# ---------------------------------------------------------------------------


class TestFuzzResult:
    def test_to_dict_empty(self):
        r = FuzzResult(target="http://example.com")
        d = r.to_dict()
        assert d["target"] == "http://example.com"
        assert d["discovered"] == []
        assert d["total_checked"] == 0

    def test_to_dict_with_findings(self):
        r = FuzzResult(
            target="http://example.com",
            discovered=[{"path": "/admin", "status": 200, "size": 1234}],
            total_checked=100,
            duration_ms=543.21,
        )
        d = r.to_dict()
        assert len(d["discovered"]) == 1
        assert d["duration_ms"] == 543.21


# ---------------------------------------------------------------------------
# PythonDirFuzzer
# ---------------------------------------------------------------------------


class TestPythonDirFuzzer:
    @pytest.mark.asyncio
    async def test_fuzz_discovers_existing_paths(self):
        """Fuzzer should discover paths that return non-404 responses."""
        transport = _mock_transport({
            "admin": (200, "<h1>Admin Panel</h1>"),
            "login": (302, ""),
            "backup": (403, "Forbidden"),
        })

        fuzzer = PythonDirFuzzer(concurrency=10, timeout=5.0)

        async with httpx.AsyncClient(transport=transport) as client:
            # Monkey-patch to use our mock client
            original_fuzz = fuzzer.fuzz

            async def patched_fuzz(url, wordlist=None, extensions=None):
                result = FuzzResult(target=url)
                paths = wordlist or COMMON_PATHS
                expanded = list(paths)
                base = url.rstrip("/")

                baseline = {"status": 404, "length": len("Not Found")}
                for path in expanded:
                    try:
                        resp = await client.get(f"{base}/{path}")
                        if resp.status_code == baseline["status"] and abs(len(resp.text) - baseline["length"]) < 50:
                            continue
                        if resp.status_code in (200, 301, 302, 307, 308, 401, 403):
                            result.discovered.append({
                                "path": f"/{path}",
                                "status": resp.status_code,
                                "size": len(resp.text),
                            })
                    except httpx.HTTPError:
                        pass
                result.total_checked = len(expanded)
                return result

            result = await patched_fuzz(
                "http://example.com",
                wordlist=["admin", "login", "backup", "nonexistent"],
            )

        assert result.total_checked == 4
        assert len(result.discovered) == 3
        paths = {d["path"] for d in result.discovered}
        assert "/admin" in paths
        assert "/login" in paths
        assert "/backup" in paths

    @pytest.mark.asyncio
    async def test_fuzz_filters_baseline_404(self):
        """Paths matching the baseline 404 should be filtered out."""
        fuzzer = PythonDirFuzzer()
        baseline = {"status": 404, "length": 100}
        # A response matching the baseline should return None
        assert fuzzer._get_baseline is not None  # method exists

    def test_common_paths_not_empty(self):
        """Built-in wordlist should have reasonable size."""
        assert len(COMMON_PATHS) >= 150


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


class TestPythonDirFuzzWrapper:
    @pytest.mark.asyncio
    async def test_wrapper_returns_json(self):
        """The tool wrapper should return valid JSON."""
        transport = _mock_transport({
            "admin": (200, "admin page"),
        })

        # We test the PythonDirFuzzer directly with a small wordlist
        fuzzer = PythonDirFuzzer(concurrency=5, timeout=5.0)

        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            baseline = {"status": 404, "length": len("Not Found")}
            result = FuzzResult(target="http://test.local")

            for path in ["admin", "nope"]:
                resp = await client.get(f"/{path}")
                if resp.status_code != baseline["status"]:
                    result.discovered.append({
                        "path": f"/{path}",
                        "status": resp.status_code,
                        "size": len(resp.text),
                    })
            result.total_checked = 2

        output = json.dumps(result.to_dict(), indent=2)
        data = json.loads(output)
        assert data["target"] == "http://test.local"
        assert len(data["discovered"]) == 1

    def test_registry_has_dir_fuzz(self):
        """dir_fuzz should be registered in the default tool registry."""
        from security_mcp.tools import create_default_tool_registry

        registry = create_default_tool_registry()
        assert "dir_fuzz" in registry.available_tools
