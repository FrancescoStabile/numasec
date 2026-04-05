"""CI/CD integration mode for numasec.

Non-interactive entry point that runs an automated security scan and produces
structured output suitable for CI pipelines.  Supports SARIF (GitHub Code
Scanning), JSON, and Markdown output formats.

Exit codes:
    0 — no findings at or above the severity threshold
    1 — findings at or above the severity threshold were detected
    2 — scan error (invalid args, timeout, unexpected failure)

Usage::

    python -m numasec.cli.ci_mode --target https://example.com --output sarif
    python -m numasec.cli.ci_mode --target https://example.com --output json --severity-threshold medium
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from typing import Any

from numasec import __version__
from numasec.models.enums import Severity
from numasec.models.finding import Finding
from numasec.reporting.markdown import generate_markdown_report
from numasec.reporting.sarif import generate_sarif_report

logger = logging.getLogger("numasec.ci")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Scan pipeline: tool name → kwargs builder (target URL is injected automatically).
SCAN_STEPS: list[dict[str, Any]] = [
    {"tool": "recon", "kwargs_key": "target"},
    {"tool": "injection_test", "kwargs_key": "url"},
    {"tool": "xss_test", "kwargs_key": "url"},
    {"tool": "auth_test", "kwargs_key": "url"},
    {"tool": "access_control_test", "kwargs_key": "url"},
    {"tool": "path_test", "kwargs_key": "url"},
]

# Mapping from vulnerability-dict "type" field to reasonable Finding defaults.
_TYPE_CWE: dict[str, str] = {
    "sql_injection": "CWE-89",
    "nosql_injection": "CWE-943",
    "ssti": "CWE-1336",
    "command_injection": "CWE-78",
    "xss": "CWE-79",
    "reflected_xss": "CWE-79",
    "dom_xss": "CWE-79",
    "csrf": "CWE-352",
    "cors": "CWE-942",
    "idor": "CWE-639",
    "lfi": "CWE-98",
    "xxe": "CWE-611",
    "open_redirect": "CWE-601",
    "host_header_injection": "CWE-644",
    "jwt_weak": "CWE-345",
    "auth_bypass": "CWE-287",
    "default_credentials": "CWE-798",
}

_TYPE_SEVERITY: dict[str, str] = {
    "sql_injection": "high",
    "nosql_injection": "high",
    "ssti": "high",
    "command_injection": "critical",
    "xss": "medium",
    "reflected_xss": "medium",
    "dom_xss": "medium",
    "csrf": "medium",
    "cors": "low",
    "idor": "high",
    "lfi": "high",
    "xxe": "high",
    "open_redirect": "low",
    "host_header_injection": "medium",
    "jwt_weak": "high",
    "auth_bypass": "critical",
    "default_credentials": "critical",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for CI mode."""
    parser = argparse.ArgumentParser(
        prog="numasec-ci",
        description="numasec CI/CD security scanner — non-interactive mode",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL to scan (e.g. https://api.example.com)",
    )
    parser.add_argument(
        "--output",
        choices=["sarif", "json", "markdown"],
        default="sarif",
        help="Output format (default: sarif)",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Fail (exit 1) if any finding meets or exceeds this severity (default: high)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Maximum scan duration in seconds (default: 300)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging to stderr",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"numasec {__version__}",
    )
    return parser.parse_args(argv)


def _vuln_to_finding(vuln: dict[str, Any], *, target: str, tool_name: str) -> Finding:
    """Convert a scanner vulnerability dict into a Finding model instance."""
    vuln_type = vuln.get("type", "unknown")
    title = vuln.get("title") or vuln_type.replace("_", " ").title()

    severity_str = vuln.get("severity", _TYPE_SEVERITY.get(vuln_type, "info"))
    try:
        severity = Severity(severity_str.lower())
    except ValueError:
        severity = Severity.INFO

    return Finding(
        title=title,
        severity=severity,
        url=vuln.get("url", target),
        description=vuln.get("description", f"{title} detected by {tool_name}"),
        evidence=vuln.get("evidence", ""),
        parameter=vuln.get("param", vuln.get("parameter", "")),
        payload=vuln.get("payload", ""),
        cwe_id=vuln.get("cwe", _TYPE_CWE.get(vuln_type, "")),
        confidence=float(vuln.get("confidence", 0.5)),
        tool_used=tool_name,
        target=target,
    )


def _extract_vulns(result: Any, tool_name: str) -> list[dict[str, Any]]:
    """Extract vulnerability dicts from a tool result.

    Handles both dict results (composite tools) and JSON-string results
    (xss_test, auth_test).
    """
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return []

    if not isinstance(result, dict):
        return []

    return list(result.get("vulnerabilities", result.get("findings", [])) or [])


def _meets_threshold(finding: Finding, threshold: str) -> bool:
    """Return True if the finding's severity meets or exceeds the threshold."""
    f_order = SEVERITY_ORDER.get(finding.severity.value, 4)
    t_order = SEVERITY_ORDER.get(threshold, 1)
    return f_order <= t_order


def _format_output(findings: list[Finding], fmt: str, target: str) -> str:
    """Render findings in the requested output format."""
    if fmt == "sarif":
        report = generate_sarif_report(
            findings,
            tool_name="numasec",
            tool_version=__version__,
            target=target,
        )
        return json.dumps(report, indent=2, ensure_ascii=False)

    if fmt == "markdown":
        return generate_markdown_report(findings, target=target)

    # json
    return json.dumps(
        {
            "target": target,
            "tool": "numasec",
            "version": __version__,
            "finding_count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings],
        },
        indent=2,
        ensure_ascii=False,
    )


async def run_ci_scan(
    target: str,
    output_format: str = "sarif",
    threshold: str = "high",
    timeout: int = 300,
    *,
    registry: Any | None = None,
) -> int:
    """Execute the CI scan pipeline and write results to stdout.

    Args:
        target: URL to scan.
        output_format: One of ``sarif``, ``json``, ``markdown``.
        threshold: Severity threshold for failure.
        timeout: Max scan time in seconds.
        registry: Optional ToolRegistry override (used in tests).

    Returns:
        Exit code (0, 1, or 2).
    """
    if registry is None:
        from numasec.mcp._singletons import get_tool_registry

        registry = get_tool_registry()

    findings: list[Finding] = []
    start = time.monotonic()
    scan_complete = True

    for step in SCAN_STEPS:
        tool_name: str = step["tool"]
        kwargs_key: str = step["kwargs_key"]
        elapsed = time.monotonic() - start
        remaining = timeout - elapsed
        if remaining <= 0:
            logger.warning("Timeout reached, skipping remaining scan steps")
            scan_complete = False
            break

        logger.info("Running %s …", tool_name)
        try:
            result = await asyncio.wait_for(
                registry.call(tool_name, **{kwargs_key: target}),
                timeout=remaining,
            )
        except TimeoutError:
            logger.warning("Timeout during %s — partial results will be used", tool_name)
            scan_complete = False
            break
        except Exception:
            logger.exception("Error running %s", tool_name)
            continue

        vulns = _extract_vulns(result, tool_name)
        for v in vulns:
            findings.append(_vuln_to_finding(v, target=target, tool_name=tool_name))

    output = _format_output(findings, output_format, target)
    sys.stdout.write(output)
    if not output.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()

    if not scan_complete:
        logger.warning("⚠ Scan incomplete due to timeout — results may have false negatives")
        sys.stderr.write("WARNING: Scan timed out before all checks completed. Results are partial.\n")

    above = [f for f in findings if _meets_threshold(f, threshold)]
    if above:
        logger.info(
            "%d finding(s) at or above '%s' threshold — exit 1",
            len(above),
            threshold,
        )
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns the process exit code."""
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return EXIT_ERROR if exc.code != 0 else EXIT_OK

    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        code = asyncio.run(
            run_ci_scan(
                target=args.target,
                output_format=args.output,
                threshold=args.severity_threshold,
                timeout=args.timeout,
            )
        )
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        code = EXIT_ERROR
    except Exception:
        logger.exception("Unexpected error during scan")
        code = EXIT_ERROR

    return code


if __name__ == "__main__":
    sys.exit(main())
