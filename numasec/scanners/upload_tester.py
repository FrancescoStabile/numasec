"""Python-native file upload vulnerability tester.

Detects unrestricted file upload vulnerabilities by probing endpoints with
various payload categories:

1. **Unrestricted type** — upload ``.php``, ``.jsp``, ``.asp``, ``.py``
   files containing a harmless marker and check for acceptance / access.
2. **MIME type bypass** — send a dangerous extension with an innocuous
   ``Content-Type`` (e.g. ``image/jpeg``).
3. **Double extension** — ``file.php.jpg``, ``file.jpg.php``.
4. **Null byte injection** — ``file.php\\x00.jpg`` in the filename.
5. **SVG XSS** — upload SVG with a benign marker (no actual scripts).
6. **Polyglot** — JPEG header followed by a harmless PHP comment marker.
7. **Content-Type mismatch** — ``application/octet-stream`` for images.

Detection strategy:
- GET the target URL and parse HTML for ``<form>`` elements with
  ``<input type="file">`` fields.
- For each discovered (or user-specified) field, attempt every payload.
- After upload, inspect the response for acceptance (2xx, no error
  keywords) and try to access the file at common upload paths.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

import httpx

from numasec.core.http import create_client

logger = logging.getLogger("numasec.scanners.upload_tester")

# ---------------------------------------------------------------------------
# Constants & payloads
# ---------------------------------------------------------------------------

_MARKER = f"NUMASEC_UPLOAD_{uuid.uuid4().hex[:8]}"
_SVG_MARKER = "NUMASEC_SVG_MARKER"

_DANGEROUS_EXTENSIONS: list[tuple[str, str]] = [
    (".php", "application/x-php"),
    (".jsp", "application/octet-stream"),
    (".asp", "application/octet-stream"),
    (".py", "text/x-python"),
]

_DOUBLE_EXTENSIONS: list[str] = [
    "file.php.jpg",
    "file.jpg.php",
    "file.php%00.jpg",
]

_NULL_BYTE_FILENAME = "file.php\x00.jpg"

_SVG_CONTENT = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
    f'<text x="10" y="20">{_SVG_MARKER}</text></svg>'
)

# Minimal JPEG header (SOI + APP0) followed by a harmless PHP comment marker.
_POLYGLOT_CONTENT = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00" + b"/* NUMASEC_POLYGLOT */"

_COMMON_UPLOAD_PATHS = [
    "/uploads/",
    "/media/",
    "/files/",
    "/static/",
    "/upload/",
    "/content/",
]

_ERROR_KEYWORDS: list[str] = [
    "error",
    "invalid",
    "not allowed",
    "rejected",
    "forbidden",
    "unsupported",
    "file type",
    "disallowed",
    "bad request",
]


# ---------------------------------------------------------------------------
# HTML form parser
# ---------------------------------------------------------------------------


class _FormParser(HTMLParser):
    """Lightweight HTML parser that extracts ``<form>`` actions and file input names."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k: v for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method") or "POST").upper(),
                "enctype": attr_map.get("enctype", ""),
                "file_inputs": [],
            }
        elif tag == "input" and self._current_form is not None and (attr_map.get("type") or "").lower() == "file":
            name = attr_map.get("name", "file")
            self._current_form["file_inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            if self._current_form["file_inputs"]:
                self.forms.append(self._current_form)
            self._current_form = None


def _parse_upload_forms(html: str) -> list[dict[str, Any]]:
    """Return list of forms that contain at least one file input."""
    parser = _FormParser()
    parser.feed(html)
    return parser.forms


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class UploadVulnerability:
    """A single file upload finding."""

    upload_type: (
        str  # "unrestricted_type" | "webshell" | "mime_bypass" | "double_ext" | "null_byte" | "svg_xss" | "polyglot"
    )
    filename_sent: str
    content_type_sent: str
    evidence: str
    severity: str = "high"
    confidence: float = 0.7


@dataclass
class UploadResult:
    """Complete file upload test result."""

    target: str
    vulnerable: bool = False
    vulnerabilities: list[UploadVulnerability] = field(default_factory=list)
    forms_found: int = 0
    upload_fields_found: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise to JSON-friendly dict."""
        return {
            "target": self.target,
            "vulnerable": self.vulnerable,
            "vulnerabilities": [
                {
                    "type": "file_upload",
                    "upload_type": v.upload_type,
                    "filename_sent": v.filename_sent,
                    "content_type_sent": v.content_type_sent,
                    "evidence": v.evidence,
                    "severity": v.severity,
                    "confidence": v.confidence,
                }
                for v in self.vulnerabilities
            ],
            "forms_found": self.forms_found,
            "upload_fields_found": self.upload_fields_found,
            "duration_ms": round(self.duration_ms, 2),
            "summary": (
                f"File upload vulnerability confirmed ({len(self.vulnerabilities)} finding(s): "
                + ", ".join(v.upload_type for v in self.vulnerabilities)
                + ")"
                if self.vulnerabilities
                else "No file upload vulnerabilities found"
            ),
            "next_steps": (
                [
                    "Verify if uploaded files are executed server-side (webshell)",
                    "Test for stored XSS via uploaded HTML/SVG files",
                    "Check if upload directory allows directory listing",
                    "Attempt to overwrite existing files via path traversal in filename",
                ]
                if self.vulnerabilities
                else []
            ),
        }


# ---------------------------------------------------------------------------
# Upload testing engine
# ---------------------------------------------------------------------------


class UploadTester:
    """Multi-technique file upload vulnerability tester.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    extra_headers:
        Additional headers for authenticated testing.
    """

    def __init__(
        self,
        timeout: float = 15.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._extra_headers = extra_headers or {}

    async def test(self, url: str, field_name: str = "", method: str = "POST") -> UploadResult:
        """Run file upload tests against a target URL.

        Args:
            url: Target URL (page with upload form **or** direct upload endpoint).
            field_name: Explicit file field name.  If empty, auto-detected from HTML.
            method: HTTP method for upload (``POST`` or ``PUT``).

        Returns:
            ``UploadResult`` with all discovered vulnerabilities.
        """
        start = time.monotonic()
        result = UploadResult(target=url)

        async with create_client(
            timeout=self.timeout,
            headers=self._extra_headers or None,
        ) as client:
            # Step 1 — discover upload forms
            fields = await self._discover_fields(client, url, field_name)
            result.forms_found = len(fields)
            result.upload_fields_found = sum(len(f["file_inputs"]) for f in fields)

            if not fields:
                # No forms discovered and no explicit field — try with defaults
                if field_name:
                    fields = [{"action": url, "method": method, "file_inputs": [field_name]}]
                else:
                    result.duration_ms = (time.monotonic() - start) * 1000
                    return result

            # Step 2 — test each field with all payload categories
            for form in fields:
                action_url = urljoin(url, form["action"]) if form["action"] else url
                upload_method = form.get("method", method)
                for fname in form["file_inputs"]:
                    await self._test_unrestricted_type(client, action_url, fname, upload_method, result)
                    await self._test_mime_bypass(client, action_url, fname, upload_method, result)
                    await self._test_double_extension(client, action_url, fname, upload_method, result)
                    await self._test_null_byte(client, action_url, fname, upload_method, result)
                    await self._test_svg_xss(client, action_url, fname, upload_method, result)
                    await self._test_polyglot(client, action_url, fname, upload_method, result)
                    await self._test_content_type_mismatch(client, action_url, fname, upload_method, result)

        result.duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            "Upload test complete: %s — %d forms, %d fields, %d vulns, %.0fms",
            url,
            result.forms_found,
            result.upload_fields_found,
            len(result.vulnerabilities),
            result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    # Form / field discovery
    # ------------------------------------------------------------------

    async def _discover_fields(
        self,
        client: httpx.AsyncClient,
        url: str,
        explicit_field: str,
    ) -> list[dict[str, Any]]:
        """GET the target page and extract forms with file inputs."""
        if explicit_field:
            return [{"action": url, "method": "POST", "file_inputs": [explicit_field]}]

        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            logger.debug("Upload form discovery error: %s", exc)
            return []

        return _parse_upload_forms(resp.text)

    # ------------------------------------------------------------------
    # Upload helper
    # ------------------------------------------------------------------

    async def _upload_file(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        filename: str,
        content: bytes,
        content_type: str,
        method: str,
    ) -> httpx.Response | None:
        """Upload a file and return the response."""
        try:
            files = {field_name: (filename, content, content_type)}
            if method.upper() == "PUT":
                return await client.put(url, files=files)
            return await client.post(url, files=files)
        except httpx.HTTPError as exc:
            logger.debug("Upload error (%s as %s): %s", filename, content_type, exc)
            return None

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _is_accepted(resp: httpx.Response) -> bool:
        """Return True if the server accepted the upload (2xx, no error keywords)."""
        if resp.status_code < 200 or resp.status_code >= 300:
            return False
        body_lower = resp.text.lower()
        return all(kw not in body_lower for kw in _ERROR_KEYWORDS)

    async def _check_file_accessible(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        filename: str,
        marker: str,
    ) -> bool:
        """Try common upload paths to see if the file is accessible and contains the marker."""
        clean_filename = filename.replace("\x00", "").replace("%00", "")
        for path in _COMMON_UPLOAD_PATHS:
            check_url = urljoin(base_url, path + clean_filename)
            try:
                resp = await client.get(check_url)
                if resp.status_code == 200 and marker in resp.text:
                    return True
            except httpx.HTTPError:
                continue
        return False

    # ------------------------------------------------------------------
    # Payload categories
    # ------------------------------------------------------------------

    async def _test_unrestricted_type(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        method: str,
        result: UploadResult,
    ) -> None:
        """Upload dangerous extensions (.php, .jsp, .asp, .py) with harmless content."""
        for ext, ct in _DANGEROUS_EXTENSIONS:
            filename = f"test{ext}"
            content = f"<!-- {_MARKER} -->".encode()
            resp = await self._upload_file(client, url, field_name, filename, content, ct, method)
            if resp is None:
                continue

            accessible = await self._check_file_accessible(client, url, filename, _MARKER)
            if accessible:
                result.vulnerabilities.append(
                    UploadVulnerability(
                        upload_type="webshell",
                        filename_sent=filename,
                        content_type_sent=ct,
                        evidence=(
                            f"Uploaded file '{filename}' is accessible and contains the marker. "
                            f"Server stores and serves uploaded files with dangerous extensions."
                        ),
                        severity="critical",
                        confidence=1.0,
                    )
                )
                result.vulnerable = True
            elif self._is_accepted(resp):
                result.vulnerabilities.append(
                    UploadVulnerability(
                        upload_type="unrestricted_type",
                        filename_sent=filename,
                        content_type_sent=ct,
                        evidence=(
                            f"Server accepted upload of '{filename}' with Content-Type '{ct}' "
                            f"without returning an error. Extension '{ext}' may be executable."
                        ),
                        severity="high",
                        confidence=0.6,
                    )
                )
                result.vulnerable = True

    async def _test_mime_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        method: str,
        result: UploadResult,
    ) -> None:
        """Send .php extension with image/jpeg Content-Type."""
        filename = "bypass.php"
        content = f"<!-- {_MARKER} -->".encode()
        resp = await self._upload_file(client, url, field_name, filename, content, "image/jpeg", method)
        if resp is None:
            return

        if self._is_accepted(resp):
            result.vulnerabilities.append(
                UploadVulnerability(
                    upload_type="mime_bypass",
                    filename_sent=filename,
                    content_type_sent="image/jpeg",
                    evidence=(
                        f"Server accepted '{filename}' with Content-Type 'image/jpeg'. "
                        f"MIME type validation may rely only on Content-Type header, "
                        f"not on file extension or magic bytes."
                    ),
                    severity="high",
                    confidence=0.7,
                )
            )
            result.vulnerable = True

    async def _test_double_extension(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        method: str,
        result: UploadResult,
    ) -> None:
        """Upload files with double extensions like file.php.jpg."""
        for filename in _DOUBLE_EXTENSIONS:
            content = f"<!-- {_MARKER} -->".encode()
            resp = await self._upload_file(client, url, field_name, filename, content, "image/jpeg", method)
            if resp is None:
                continue

            if self._is_accepted(resp):
                result.vulnerabilities.append(
                    UploadVulnerability(
                        upload_type="double_ext",
                        filename_sent=filename,
                        content_type_sent="image/jpeg",
                        evidence=(
                            f"Server accepted file with double extension '{filename}'. "
                            f"If the server processes the first extension, "
                            f"the file may be executed as PHP/JSP."
                        ),
                        severity="high",
                        confidence=0.8,
                    )
                )
                result.vulnerable = True
                break  # One finding per category is sufficient

    async def _test_null_byte(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        method: str,
        result: UploadResult,
    ) -> None:
        """Upload with null byte in filename: file.php\\x00.jpg."""
        filename = _NULL_BYTE_FILENAME
        content = f"<!-- {_MARKER} -->".encode()
        resp = await self._upload_file(client, url, field_name, filename, content, "image/jpeg", method)
        if resp is None:
            return

        if self._is_accepted(resp):
            result.vulnerabilities.append(
                UploadVulnerability(
                    upload_type="null_byte",
                    filename_sent=repr(filename),
                    content_type_sent="image/jpeg",
                    evidence=(
                        "Server accepted file with null byte in filename "
                        f"('{repr(filename)}'). Null byte may truncate the "
                        "filename to 'file.php' on the server side."
                    ),
                    severity="high",
                    confidence=0.8,
                )
            )
            result.vulnerable = True

    async def _test_svg_xss(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        method: str,
        result: UploadResult,
    ) -> None:
        """Upload SVG with benign marker content."""
        filename = "image.svg"
        content = _SVG_CONTENT.encode()
        resp = await self._upload_file(client, url, field_name, filename, content, "image/svg+xml", method)
        if resp is None:
            return

        accessible = await self._check_file_accessible(client, url, filename, _SVG_MARKER)
        if accessible:
            result.vulnerabilities.append(
                UploadVulnerability(
                    upload_type="svg_xss",
                    filename_sent=filename,
                    content_type_sent="image/svg+xml",
                    evidence=(
                        f"Uploaded SVG file is accessible and contains the marker '{_SVG_MARKER}'. "
                        "An attacker could embed JavaScript in an SVG for stored XSS."
                    ),
                    severity="high",
                    confidence=1.0,
                )
            )
            result.vulnerable = True
        elif self._is_accepted(resp):
            result.vulnerabilities.append(
                UploadVulnerability(
                    upload_type="svg_xss",
                    filename_sent=filename,
                    content_type_sent="image/svg+xml",
                    evidence=(
                        "Server accepted SVG upload without error. "
                        "If served inline, SVG files can execute embedded JavaScript."
                    ),
                    severity="medium",
                    confidence=0.5,
                )
            )
            result.vulnerable = True

    async def _test_polyglot(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        method: str,
        result: UploadResult,
    ) -> None:
        """Upload JPEG header + harmless PHP comment marker (polyglot)."""
        filename = "image.php.jpg"
        content = _POLYGLOT_CONTENT
        resp = await self._upload_file(client, url, field_name, filename, content, "image/jpeg", method)
        if resp is None:
            return

        if self._is_accepted(resp):
            result.vulnerabilities.append(
                UploadVulnerability(
                    upload_type="polyglot",
                    filename_sent=filename,
                    content_type_sent="image/jpeg",
                    evidence=(
                        f"Server accepted polyglot file '{filename}' (JPEG header + PHP comment). "
                        "File passes magic-byte checks but may be executed as PHP "
                        "if the server processes the .php extension."
                    ),
                    severity="high",
                    confidence=0.7,
                )
            )
            result.vulnerable = True

    async def _test_content_type_mismatch(
        self,
        client: httpx.AsyncClient,
        url: str,
        field_name: str,
        method: str,
        result: UploadResult,
    ) -> None:
        """Send application/octet-stream for an image upload."""
        filename = "photo.jpg"
        content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
        resp = await self._upload_file(
            client,
            url,
            field_name,
            filename,
            content,
            "application/octet-stream",
            method,
        )
        if resp is None:
            return

        if self._is_accepted(resp):
            result.vulnerabilities.append(
                UploadVulnerability(
                    upload_type="mime_bypass",
                    filename_sent=filename,
                    content_type_sent="application/octet-stream",
                    evidence=(
                        f"Server accepted '{filename}' with Content-Type 'application/octet-stream'. "
                        "Content-Type validation may be missing or insufficient."
                    ),
                    severity="medium",
                    confidence=0.5,
                )
            )
            result.vulnerable = True


# ---------------------------------------------------------------------------
# Tool wrapper for ToolRegistry
# ---------------------------------------------------------------------------


async def python_upload_test(
    url: str,
    field_name: str = "",
    headers: str | None = None,
) -> str:
    """Test URL for file upload vulnerabilities.

    Discovers ``<input type="file">`` fields in HTML forms and probes each
    with dangerous extensions, MIME bypass, double extensions, null byte
    injection, SVG XSS, polyglot files, and Content-Type mismatch payloads.

    Args:
        url: Target URL (page with upload form or direct upload endpoint).
        field_name: Explicit file field name.  Auto-detected if omitted.
        headers: Optional JSON string of HTTP headers for authenticated
            testing, e.g. ``'{"Authorization": "Bearer token123"}'``.

    Returns:
        JSON string with ``UploadResult`` data.
    """
    import contextlib

    extra_headers: dict[str, str] | None = None
    if headers:
        if isinstance(headers, dict):
            extra_headers = headers
        else:
            with contextlib.suppress(json.JSONDecodeError):
                extra_headers = json.loads(headers)

    tester = UploadTester(extra_headers=extra_headers)
    result = await tester.test(url, field_name=field_name)
    return json.dumps(result.to_dict(), indent=2)
