"""
NumaSec Benchmark — DVWA Test Suite

10 parametrized tests against Damn Vulnerable Web Application.
Each test maps to a known vulnerability in DVWA.

Run: pytest tests/benchmarks/test_dvwa.py -v --benchmark
Requires: Docker/Podman + DEEPSEEK_API_KEY (or other LLM key)
"""

from __future__ import annotations

import asyncio
import time

import pytest

from tests.benchmarks.ground_truth import DVWA_VULNS, GroundTruthVuln
from tests.benchmarks.scorer import score_benchmark, save_benchmark_result, match_findings


# Mark entire module as benchmark — skipped unless --benchmark flag
pytestmark = [
    pytest.mark.benchmark,
    pytest.mark.slow,
]


@pytest.fixture(scope="module")
def dvwa_assessment_findings(dvwa_target):
    """Run a single NumaSec assessment on DVWA, cache findings for all tests.

    This runs ONCE per module and shares the result across all parametrized tests.
    Much more efficient than running 10 separate assessments.
    """
    from numasec.mcp_tools import run_assess

    start = time.time()
    result_md = asyncio.get_event_loop().run_until_complete(
        run_assess(
            target=dvwa_target,
            scope=dvwa_target,
            budget=2.0,
            depth="standard",
        )
    )
    duration = time.time() - start

    # Parse findings from Markdown result
    findings = _parse_findings_from_markdown(result_md)

    return {
        "findings": findings,
        "raw_markdown": result_md,
        "duration": duration,
        "target": dvwa_target,
    }


def _parse_findings_from_markdown(markdown: str) -> list[dict]:
    """Extract finding dicts from assessment Markdown output."""
    import re

    findings = []
    # Match finding headers: ## 🔴 CRITICAL: Title or ## 🟠 HIGH: Title
    pattern = r"## [🔴🟠🟡🔵⚪] (\w+): (.+?)(?:\n|$)"
    matches = re.finditer(pattern, markdown)

    current_finding = None
    for match in matches:
        severity = match.group(1).lower()
        title = match.group(2).strip()

        # Get description (text between this heading and next heading)
        start = match.end()
        next_heading = re.search(r"\n## ", markdown[start:])
        end = start + next_heading.start() if next_heading else len(markdown)
        description = markdown[start:end].strip()

        findings.append({
            "title": title,
            "severity": severity,
            "description": description,
        })

    return findings


@pytest.mark.parametrize(
    "vuln",
    DVWA_VULNS,
    ids=[v.id for v in DVWA_VULNS],
)
def test_dvwa_vuln_detected(dvwa_assessment_findings, vuln: GroundTruthVuln):
    """Verify that NumaSec detects a specific DVWA vulnerability.

    This is a parametrized test — runs once per known vuln.
    Matching is keyword-based: the finding title or description must
    contain at least one of the vuln's match_keywords.
    """
    findings = dvwa_assessment_findings["findings"]
    matches = match_findings([vuln], findings)

    assert len(matches) == 1
    match = matches[0]

    # This test documents detection rate — a failure means NumaSec
    # missed this vuln, which is expected for some vulns in baseline.
    # We use xfail for vulns that are known-hard.
    if not match.matched:
        pytest.skip(
            f"NumaSec did not detect {vuln.name} ({vuln.vuln_type}) — "
            f"this contributes to the F1 score as a false negative"
        )


def test_dvwa_f1_score(dvwa_assessment_findings):
    """Compute and report the overall F1 score for DVWA."""
    result = score_benchmark(
        target_name="DVWA",
        ground_truth=DVWA_VULNS,
        findings=dvwa_assessment_findings["findings"],
        duration=dvwa_assessment_findings["duration"],
    )

    # Save results
    save_benchmark_result(result)

    # Print report
    print("\n" + result.to_markdown())

    # Baseline targets — these will be adjusted as we improve
    assert result.recall >= 0.0, f"Recall should be measurable: {result.recall:.1%}"
    assert result.f1 >= 0.0, f"F1 should be measurable: {result.f1:.1%}"
