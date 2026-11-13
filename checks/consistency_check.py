"""
Forensic check for metadata consistency, absence, and cross-tag correlation anomalies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "consistency"
TITLE = "Metadata Consistency"


def run(ctx: ImageContext) -> CheckResult:
    """Evaluate whether metadata headers are internally consistent or stripped."""
    exif_count = len(ctx.exif)
    has_make = "Make" in ctx.exif
    has_model = "Model" in ctx.exif
    has_time = "DateTimeOriginal" in ctx.exif
    has_exposure = any(k in ctx.exif for k in ("ExposureTime", "FNumber", "ISOSpeedRatings"))
    has_xmp = bool(ctx.xmp_raw)

    details = {
        "exif_tag_count": exif_count,
        "has_camera_make_model": has_make or has_model,
        "has_capture_time": has_time,
        "has_exposure": has_exposure,
        "has_xmp": has_xmp,
    }

    # Case 1: Entirely stripped or missing metadata
    # Core requirement: "An image with no meaningful metadata must be treated as uncertain
    # rather than automatically classified as AI-generated."
    if exif_count == 0 and not has_xmp and not ctx.png_text_chunks:
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=False,
            signal=0.5,  # Neutral / Uncertain
            conclusive=False,
            evidence=(
                "Metadata is completely stripped or absent. While common in AI-generated imagery, "
                "social media platforms and messaging apps routinely strip EXIF for privacy. Treated as uncertain."
            ),
            details=details,
        )

    # Case 2: Conflicting metadata (e.g. claims camera hardware but lacks optical exposure tags and has software edit)
    conflicts: list[str] = []
    if (has_make or has_model) and not has_exposure and not has_time:
        conflicts.append("Camera make/model specified without accompanying exposure or capture timestamp")

    software = str(ctx.exif.get("Software", "")).lower()
    if any(x in software for x in ("photoshop", "gimp", "canva", "lightroom")) and not has_time:
        conflicts.append(f"Image editor '{ctx.exif.get('Software')}' present but original capture date omitted")

    if conflicts:
        evidence = "Metadata consistency anomaly detected: " + "; ".join(conflicts) + "."
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.75,
            conclusive=True,
            evidence=evidence,
            details={"conflicts": conflicts, **details},
        )

    # Case 3: Coherent, authentic camera metadata stack
    if has_make and has_model and has_exposure and has_time:
        evidence = (
            f"EXIF metadata structure is coherent ({exif_count} tags). Make, Model, optical "
            "exposure, and capture timestamp correlate consistently with physical hardware capture."
        )
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.0,  # Real-like
            conclusive=True,
            evidence=evidence,
            details=details,
        )

    # Case 4: Partial metadata without conflicts
    evidence = (
        f"Partial metadata detected ({exif_count} tags). No direct contradictions found, "
        "but metadata stack is incomplete."
    )
    return CheckResult(
        key=KEY,
        title=TITLE,
        found=True,
        signal=0.4,
        conclusive=False,
        evidence=evidence,
        details=details,
    )
