"""
Forensic scoring engine for TruePic.
Calculates heuristic risk scores, confidence levels, and weighted contributions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from checks.base import CheckResult


def get_risk_level(score: int) -> str:
    """Map numeric risk score to standardized forensic risk tier."""
    if score <= 20:
        return "Low"
    elif score <= 40:
        return "Low-Medium"
    elif score <= 65:
        return "Inconclusive"
    elif score <= 85:
        return "High"
    else:
        return "Very High"


def get_confidence_level(ratio: float) -> str:
    """Map ratio of conclusive weighted evidence to confidence rating."""
    pct = ratio * 100.0
    if pct >= 70.0:
        return "High"
    elif pct >= 40.0:
        return "Medium"
    else:
        return "Low"


def calculate_risk(
    results: list[CheckResult],
    weights: dict[str, int],
) -> dict[str, Any]:
    """Calculate the overall forensic authenticity risk score and confidence metrics.

    Formula:
        Risk Score = round(sum(weight * signal) / sum(active weights) * 100)

    Rules:
        - Exclude skipped checks from denominator and rescale active weights.
        - Direct explicit AI marker or validated AI C2PA declaration floors risk score at 90.
        - Missing metadata or missing camera info alone does not trigger high risk.
        - When direct AI markers are present, absence of physical optical hardware corroborates
          the synthetic determination and reinforces confidence.
    """
    total_weighted_signal = 0.0
    active_weight_sum = 0
    conclusive_weight_sum = 0

    has_explicit_c2pa_ai = False
    has_explicit_ai_marker = False

    for res in results:
        w = weights.get(res.key, 0)

        # Informational or skipped checks do not contribute to active denominator
        if w <= 0 or res.skipped:
            continue

        active_weight_sum += w
        total_weighted_signal += w * res.signal

        if res.conclusive:
            conclusive_weight_sum += w

        # Direct explicit markers checks
        if res.key == "c2pa" and res.found and res.signal >= 0.9:
            has_explicit_c2pa_ai = True
        if res.key == "ai_markers" and res.found and res.signal >= 0.9:
            has_explicit_ai_marker = True

    # Compute base risk score
    if active_weight_sum > 0:
        base_score = round((total_weighted_signal / active_weight_sum) * 100)
    else:
        base_score = 50

    risk_score = max(0, min(100, base_score))
    override_applied = False
    override_reason: str | None = None

    # Rule: Explicit AI marker or validated AI C2PA manifest forces score to >= 90
    if has_explicit_c2pa_ai or has_explicit_ai_marker:
        if risk_score < 90:
            risk_score = 90
            override_applied = True
            reasons = []
            if has_explicit_c2pa_ai:
                reasons.append("validated C2PA manifest declaring AI generation")
            if has_explicit_ai_marker:
                reasons.append("explicit generative AI parameters/markers")
            override_reason = (
                f"Risk score raised to 90 due to direct confirmation of {', '.join(reasons)}."
            )

    # Calculate confidence:
    # When direct AI markers or C2PA AI declarations are present, absence of optical hardware
    # metadata (camera, exposure, makernote, capture time, GPS) corroborates the synthetic
    # classification, providing high confidence.
    if has_explicit_c2pa_ai or has_explicit_ai_marker:
        corroborating_keys = {"camera", "exposure", "makernote", "capture_time", "gps"}
        effective_conclusive_weight = conclusive_weight_sum
        for res in results:
            if res.key in corroborating_keys and not res.found and not res.skipped:
                effective_conclusive_weight += weights.get(res.key, 0)

        raw_ratio = (
            (effective_conclusive_weight / active_weight_sum) if active_weight_sum > 0 else 0.85
        )
        # Direct confirmed AI marker or manifest guarantees High confidence (>= 80%)
        confidence_ratio = min(1.0, max(0.80, raw_ratio))
        display_conclusive_pts = round(confidence_ratio * active_weight_sum)
    else:
        confidence_ratio = (
            (conclusive_weight_sum / active_weight_sum) if active_weight_sum > 0 else 0.0
        )
        display_conclusive_pts = conclusive_weight_sum

    confidence_level = get_confidence_level(confidence_ratio)
    risk_level = get_risk_level(risk_score)

    explanation = (
        f"Calculated from {active_weight_sum} active points across weighted forensic checks. "
        f"{display_conclusive_pts} points ({round(confidence_ratio * 100)}%) derived from conclusive indicators. "
        "Score represents a probabilistic heuristic indicator of artificial manipulation or generation."
    )
    if override_reason:
        explanation += f" Note: {override_reason}"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence_level,
        "confidence_percentage": round(confidence_ratio * 100, 1),
        "explanation": explanation,
        "active_weight_total": active_weight_sum,
        "conclusive_weight_total": display_conclusive_pts,
        "override_applied": override_applied,
        "override_reason": override_reason,
    }
