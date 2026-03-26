"""Benchmark scoring against ground truth."""

from __future__ import annotations

from typing import Any

# Severity weights for weighted recall — critical/high findings matter more
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
    "info": 0.25,
}


def _types_match(finding_type: str, gt_type: str, aliases: dict[str, list[str]] | None = None) -> bool:
    """Check if a finding type matches a ground-truth type.

    Matching strategy (ordered):
    1. Exact match (case-insensitive)
    2. Substring match (either direction)
    3. Alias match: finding type appears in the alias list for gt_type
    """
    ft = finding_type.lower().strip()
    gt = gt_type.lower().strip()

    # Exact
    if ft == gt:
        return True

    # Substring
    if ft in gt or gt in ft:
        return True

    # Alias
    if aliases:
        gt_aliases = aliases.get(gt, [])
        if ft in gt_aliases:
            return True
        # Reverse: if the finding uses a canonical name that aliases to the GT
        for canonical, alias_list in aliases.items():
            if ft == canonical and gt in alias_list:
                return True

    return False


def _location_match(finding: dict[str, Any], gt: dict[str, Any]) -> bool:
    """Optional location matching — boosts confidence when both type and location match.

    Returns True if no location info is available (permissive) or if locations overlap.
    """
    f_loc = finding.get("location", "").lower().strip()
    gt_loc = gt.get("location", "").lower().strip()

    if not f_loc or not gt_loc:
        return True  # Can't compare, allow type-only match

    return f_loc in gt_loc or gt_loc in f_loc


def calculate_scores(
    findings: list[dict[str, Any]],
    ground_truth: list[dict[str, Any]],
    aliases: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """
    Calculate precision, recall, weighted recall, and F1 against ground truth.

    Matching is done by vulnerability type (case-insensitive substring + alias lookup).
    ``weighted_recall`` weights each ground-truth vuln by severity so missing
    a critical finding penalises more than missing an info finding.

    Args:
        findings: List of detected findings with at least ``type`` key.
        ground_truth: List of expected vulns with ``type`` and ``severity``.
        aliases: Optional type alias map (e.g. from ground_truth._TYPE_ALIASES).

    Returns:
        Dict with precision, recall, weighted_recall, f1, true_positives,
        and a detailed ``matches`` list showing which findings matched which GT entries.
    """
    if not findings and not ground_truth:
        return {
            "precision": 1.0, "recall": 1.0, "weighted_recall": 1.0,
            "f1": 1.0, "true_positives": 0, "matches": [], "unmatched_gt": [], "unmatched_findings": [],
        }

    if not findings:
        return {
            "precision": 0.0, "recall": 0.0, "weighted_recall": 0.0,
            "f1": 0.0, "true_positives": 0, "matches": [],
            "unmatched_gt": [gt.get("type", "") for gt in ground_truth],
            "unmatched_findings": [],
        }

    if not ground_truth:
        return {
            "precision": 0.0, "recall": 0.0, "weighted_recall": 0.0,
            "f1": 0.0, "true_positives": 0, "matches": [],
            "unmatched_gt": [],
            "unmatched_findings": [f.get("type", "") for f in findings],
        }

    # Match findings to ground truth by type (+ optional location)
    matched_gt: set[int] = set()
    matched_findings: set[int] = set()
    matches: list[dict[str, str]] = []

    # Pass 1: Prefer type + location matches
    for fi, finding in enumerate(findings):
        finding_type = finding.get("type", "").lower()
        for gi, gt in enumerate(ground_truth):
            if gi in matched_gt:
                continue
            gt_type = gt.get("type", "").lower()
            if _types_match(finding_type, gt_type, aliases) and _location_match(finding, gt):
                matched_gt.add(gi)
                matched_findings.add(fi)
                matches.append({
                    "finding_type": finding_type,
                    "gt_type": gt_type,
                    "gt_location": gt.get("location", ""),
                    "finding_location": finding.get("location", ""),
                })
                break

    # Pass 2: Type-only matches for unmatched findings
    for fi, finding in enumerate(findings):
        if fi in matched_findings:
            continue
        finding_type = finding.get("type", "").lower()
        for gi, gt in enumerate(ground_truth):
            if gi in matched_gt:
                continue
            gt_type = gt.get("type", "").lower()
            if _types_match(finding_type, gt_type, aliases):
                matched_gt.add(gi)
                matched_findings.add(fi)
                matches.append({
                    "finding_type": finding_type,
                    "gt_type": gt_type,
                    "gt_location": gt.get("location", ""),
                    "finding_location": finding.get("location", ""),
                })
                break

    true_positives = len(matched_gt)
    precision = true_positives / len(findings) if findings else 0.0
    recall = true_positives / len(ground_truth) if ground_truth else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # Weighted recall: sum(matched_weight) / sum(total_weight)
    total_weight = sum(_SEVERITY_WEIGHTS.get(gt.get("severity", "medium"), 1.0) for gt in ground_truth)
    matched_weight = sum(
        _SEVERITY_WEIGHTS.get(ground_truth[i].get("severity", "medium"), 1.0) for i in matched_gt
    )
    weighted_recall = matched_weight / total_weight if total_weight > 0 else 0.0

    unmatched_gt = [
        {"type": ground_truth[i].get("type", ""), "location": ground_truth[i].get("location", "")}
        for i in range(len(ground_truth))
        if i not in matched_gt
    ]
    unmatched_findings = [
        {"type": findings[i].get("type", ""), "location": findings[i].get("location", "")}
        for i in range(len(findings))
        if i not in matched_findings
    ]

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "weighted_recall": round(weighted_recall, 4),
        "f1": round(f1, 4),
        "true_positives": true_positives,
        "matches": matches,
        "unmatched_gt": unmatched_gt,
        "unmatched_findings": unmatched_findings,
    }
