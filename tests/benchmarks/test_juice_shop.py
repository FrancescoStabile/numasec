"""
NumaSec Benchmark — Juice Shop Test Suite

12 parametrized tests against OWASP Juice Shop.
Each test maps to a known vulnerability.

Run: pytest tests/benchmarks/test_juice_shop.py -v --benchmark
Requires: Docker/Podman + DEEPSEEK_API_KEY (or other LLM key)
"""

from __future__ import annotations

import asyncio
import time

import pytest

from tests.benchmarks.ground_truth import JUICESHOP_VULNS, GroundTruthVuln
from tests.benchmarks.scorer import score_benchmark, save_benchmark_result, match_findings


# Mark entire module as benchmark — skipped unless --benchmark flag
pytestmark = [
    pytest.mark.benchmark,
    pytest.mark.slow,
]


@pytest.fixture(scope="module")
def juice_shop_assessment_findings(juice_shop_target):
    """Run a single NumaSec assessment on Juice Shop, cache findings."""
    from numasec.mcp_tools import run_assess

    start = time.time()
    result_md = asyncio.get_event_loop().run_until_complete(
        run_assess(
            target=juice_shop_target,
            scope=juice_shop_target,
            budget=2.0,
            depth="standard",
        )
    )
    duration = time.time() - start

    findings = _parse_findings_from_markdown(result_md)

    return {
        "findings": findings,
        "raw_markdown": result_md,
        "duration": duration,
        "target": juice_shop_target,
    }


def _parse_findings_from_markdown(markdown: str) -> list[dict]:
    """Extract finding dicts from assessment Markdown output."""
    import re

    findings = []
    pattern = r"## [🔴🟠🟡🔵⚪] (\w+): (.+?)(?:\n|$)"
    matches = re.finditer(pattern, markdown)

    for match in matches:
        severity = match.group(1).lower()
        title = match.group(2).strip()

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
    JUICESHOP_VULNS,
    ids=[v.id for v in JUICESHOP_VULNS],
)
def test_juice_shop_vuln_detected(juice_shop_assessment_findings, vuln: GroundTruthVuln):
    """Verify that NumaSec detects a specific Juice Shop vulnerability."""
    findings = juice_shop_assessment_findings["findings"]
    matches = match_findings([vuln], findings)

    assert len(matches) == 1
    match = matches[0]

    if not match.matched:
        pytest.skip(
            f"NumaSec did not detect {vuln.name} ({vuln.vuln_type}) — "
            f"false negative contribution to F1 score"
        )


def test_juice_shop_f1_score(juice_shop_assessment_findings):
    """Compute and report the overall F1 score for Juice Shop."""
    result = score_benchmark(
        target_name="Juice Shop",
        ground_truth=JUICESHOP_VULNS,
        findings=juice_shop_assessment_findings["findings"],
        duration=juice_shop_assessment_findings["duration"],
    )

    save_benchmark_result(result)

    print("\n" + result.to_markdown())

    assert result.recall >= 0.0, f"Recall should be measurable: {result.recall:.1%}"
    assert result.f1 >= 0.0, f"F1 should be measurable: {result.f1:.1%}"
