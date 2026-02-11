"""
NumaSec Benchmark — F1 / Precision / Recall Scorer

Compares agent findings against ground truth to produce benchmark metrics.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from tests.benchmarks.ground_truth import GroundTruthVuln

logger = logging.getLogger("numasec.benchmark.scorer")


@dataclass
class MatchResult:
    """Result of matching a single ground truth vuln against findings."""
    vuln: GroundTruthVuln
    matched: bool = False
    matched_finding_title: str = ""
    confidence: float = 0.0


@dataclass
class BenchmarkResult:
    """Complete benchmark scoring result."""
    target_name: str
    ground_truth: list[GroundTruthVuln]
    findings: list[dict[str, Any]]
    matches: list[MatchResult] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)

    # Computed metrics
    true_positives: int = 0
    false_negatives: int = 0
    false_positive_count: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0

    # Metadata
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    provider: str = ""
    numasec_version: str = ""
    timestamp: str = ""

    def compute(self) -> None:
        """Compute precision, recall, F1 from matches."""
        self.true_positives = sum(1 for m in self.matches if m.matched)
        self.false_negatives = sum(1 for m in self.matches if not m.matched)

        # Find false positives: findings that didn't match any ground truth
        matched_titles = {m.matched_finding_title for m in self.matches if m.matched}
        self.false_positives = [
            f for f in self.findings
            if f.get("title", "") not in matched_titles
        ]
        self.false_positive_count = len(self.false_positives)

        # Precision = TP / (TP + FP)
        total_positive = self.true_positives + self.false_positive_count
        self.precision = self.true_positives / total_positive if total_positive > 0 else 0.0

        # Recall = TP / (TP + FN)
        total_actual = self.true_positives + self.false_negatives
        self.recall = self.true_positives / total_actual if total_actual > 0 else 0.0

        # F1 = 2 * (P * R) / (P + R)
        pr_sum = self.precision + self.recall
        self.f1 = 2 * (self.precision * self.recall) / pr_sum if pr_sum > 0 else 0.0

        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            "target": self.target_name,
            "metrics": {
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1": round(self.f1, 4),
                "true_positives": self.true_positives,
                "false_negatives": self.false_negatives,
                "false_positives": self.false_positive_count,
            },
            "ground_truth_count": len(self.ground_truth),
            "findings_count": len(self.findings),
            "matches": [
                {
                    "vuln_id": m.vuln.id,
                    "vuln_name": m.vuln.name,
                    "matched": m.matched,
                    "matched_finding": m.matched_finding_title,
                    "confidence": m.confidence,
                }
                for m in self.matches
            ],
            "false_positive_findings": [
                {"title": f.get("title", ""), "severity": f.get("severity", "")}
                for f in self.false_positives
            ],
            "metadata": {
                "duration_seconds": round(self.duration_seconds, 1),
                "cost_usd": round(self.cost_usd, 4),
                "provider": self.provider,
                "numasec_version": self.numasec_version,
                "timestamp": self.timestamp,
            },
        }

    def to_markdown(self) -> str:
        """Generate a human-readable Markdown summary."""
        lines = [
            f"# Benchmark: {self.target_name}",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| **F1 Score** | **{self.f1:.1%}** |",
            f"| Precision | {self.precision:.1%} |",
            f"| Recall | {self.recall:.1%} |",
            f"| True Positives | {self.true_positives} |",
            f"| False Negatives | {self.false_negatives} |",
            f"| False Positives | {self.false_positive_count} |",
            f"| Duration | {self.duration_seconds:.0f}s |",
            f"| Cost | ${self.cost_usd:.2f} |",
            f"| Provider | {self.provider} |",
            "",
            "## Detection Results",
            "",
        ]

        for m in self.matches:
            icon = "✅" if m.matched else "❌"
            matched_str = f" → `{m.matched_finding_title}`" if m.matched else ""
            lines.append(f"- {icon} **{m.vuln.name}** ({m.vuln.severity}){matched_str}")

        if self.false_positives:
            lines.append("")
            lines.append("## False Positives")
            lines.append("")
            for f in self.false_positives:
                lines.append(f"- ⚠️ {f.get('title', 'Unknown')} ({f.get('severity', '?')})")

        return "\n".join(lines)


def match_findings(
    ground_truth: list[GroundTruthVuln],
    findings: list[dict[str, Any]],
) -> list[MatchResult]:
    """Match agent findings against ground truth vulnerabilities.

    Uses keyword matching: a finding is considered a true positive if
    its title or description contains ANY of the ground truth vuln's
    match_keywords.

    Args:
        ground_truth: Known vulnerabilities to check for
        findings: Agent findings (list of dicts with 'title', 'description', 'severity')

    Returns:
        List of MatchResult for each ground truth vulnerability
    """
    results = []
    used_findings: set[int] = set()  # Prevent double-matching

    for vuln in ground_truth:
        match = MatchResult(vuln=vuln)

        for i, finding in enumerate(findings):
            if i in used_findings:
                continue

            title = finding.get("title", "").lower()
            desc = finding.get("description", "").lower()
            combined = f"{title} {desc}"

            # Check if any keyword matches
            for keyword in vuln.match_keywords:
                if keyword.lower() in combined:
                    match.matched = True
                    match.matched_finding_title = finding.get("title", "")
                    match.confidence = 1.0
                    used_findings.add(i)
                    break

            if match.matched:
                break

        results.append(match)

    return results


def score_benchmark(
    target_name: str,
    ground_truth: list[GroundTruthVuln],
    findings: list[dict[str, Any]],
    duration: float = 0.0,
    cost: float = 0.0,
    provider: str = "",
) -> BenchmarkResult:
    """Score a benchmark run against ground truth.

    Args:
        target_name: Name of the benchmark target (e.g. "DVWA", "Juice Shop")
        ground_truth: Known vulnerabilities
        findings: Agent findings as list of dicts
        duration: Assessment duration in seconds
        cost: Total cost in USD
        provider: LLM provider used

    Returns:
        BenchmarkResult with computed metrics
    """
    from numasec import __version__

    matches = match_findings(ground_truth, findings)

    result = BenchmarkResult(
        target_name=target_name,
        ground_truth=ground_truth,
        findings=findings,
        matches=matches,
        duration_seconds=duration,
        cost_usd=cost,
        provider=provider,
        numasec_version=__version__,
    )
    result.compute()

    return result


def save_benchmark_result(
    result: BenchmarkResult,
    output_dir: Path | str = "tests/benchmarks/results",
) -> Path:
    """Save benchmark result to JSON file.

    Args:
        result: Computed benchmark result
        output_dir: Directory to save results

    Returns:
        Path to saved JSON file
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{result.target_name.lower().replace(' ', '_')}_{timestamp}.json"
    filepath = output_dir / filename

    filepath.write_text(json.dumps(result.to_dict(), indent=2))
    logger.info(f"Benchmark result saved to {filepath}")

    return filepath
