"""
Forensic check for metadata consistency, absence, and cross-tag correlation anomalies.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "consistency"
TITLE = "Metadata Consistency"

AI_SOFTWARE_SIGNATURES = (
    "stable diffusion",
    "stablediffusion",
    "automatic1111",
    "comfyui",
    "midjourney",
    "dall-e",
    "dalle",
    "novelai",
    "invokeai",
    "dreamstudio",
    "adobe firefly",
    "fooocus",
    "ideogram",
    "flux.1",
    "synthid",
)

IPTC_ALGORITHMIC_URI = "digitalsourcetype/trainedalgorithmicmedia"

DIFFUSION_PARAM_PATTERNS = [
    r"steps:\s*\d+",
    r"sampler:\s*[\w\+]+",
    r"cfg scale:\s*[\d\.]+",
    r"seed:\s*\d+",
    r"negative prompt:",
    r"denoising strength:\s*[\d\.]+",
]


def _detect_ai_in_context(ctx: ImageContext) -> bool:
    """Check if any AI generator markers exist in context metadata."""
    # Check PNG chunks
    for k, v in ctx.png_text_chunks.items():
        k_lower, v_lower = k.lower(), v.lower()
        if k_lower in ("prompt", "workflow") and any(x in v_lower for x in ("class_type", "ksampler")):
            return True
        if k_lower == "parameters":
            return True
        if any(sig in v_lower for sig in AI_SOFTWARE_SIGNATURES):
            return True

    # Check EXIF Software and UserComment
    software = str(ctx.exif.get("Software", "")).lower()
    if any(sig in software for sig in AI_SOFTWARE_SIGNATURES):
        return True

    comment = str(ctx.exif.get("UserComment", "")).lower()
    if any(re.search(p, comment) for p in DIFFUSION_PARAM_PATTERNS):
        return True

    # Check XMP
    if ctx.xmp_raw:
        xmp_lower = ctx.xmp_raw.lower()
        if IPTC_ALGORITHMIC_URI in xmp_lower:
            return True
        if any(sig in xmp_lower for sig in AI_SOFTWARE_SIGNATURES):
            return True

    # Check C2PA
    if ctx.c2pa_manifest:
        import json
        m_str = json.dumps(ctx.c2pa_manifest).lower()
        if "trainedalgorithmicmedia" in m_str or "ai_generated" in m_str:
            return True

    return False


def run(ctx: ImageContext) -> CheckResult:
    """Evaluate whether metadata headers are internally consistent or stripped."""
    exif_count = len(ctx.exif)
    has_make = "Make" in ctx.exif
    has_model = "Model" in ctx.exif
    has_time = "DateTimeOriginal" in ctx.exif
    has_exposure = any(k in ctx.exif for k in ("ExposureTime", "FNumber", "ISOSpeedRatings"))
    has_xmp = bool(ctx.xmp_raw)
    has_ai = _detect_ai_in_context(ctx)

    details = {
        "exif_tag_count": exif_count,
        "has_camera_make_model": has_make or has_model,
        "has_capture_time": has_time,
        "has_exposure": has_exposure,
        "has_xmp": has_xmp,
        "has_ai_indicators": has_ai,
    }

    # Case 1: AI generation markers present
    if has_ai:
        if has_make or has_model or has_exposure:
            # Contradiction: Claims physical camera but contains AI parameters
            evidence = (
                "Severe metadata contradiction: Physical camera hardware metadata present "
                "while generative AI parameters/signatures are simultaneously embedded."
            )
            return CheckResult(
                key=KEY,
                title=TITLE,
                found=True,
                signal=1.0,  # Blatant contradiction / anomaly
                conclusive=True,
                evidence=evidence,
                details={"contradiction": "Camera EXIF with AI parameters", **details},
            )
        else:
            # Coherent synthetic media container: AI parameters present with absence of camera headers
            evidence = (
                "Metadata is internally coherent for synthetic media: Generative AI workflow "
                "parameters present with expected absence of physical optical camera sensor tags."
            )
            return CheckResult(
                key=KEY,
                title=TITLE,
                found=True,
                signal=0.90,  # AI-consistent
                conclusive=True,
                evidence=evidence,
                details={"profile": "Synthetic media container", **details},
            )

    # Case 2: Entirely stripped or missing metadata
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

    # Case 3: Conflicting metadata (e.g. claims camera hardware but lacks optical exposure tags and has software edit)
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

    # Case 4: Coherent, authentic camera metadata stack
    if (has_make or has_model) and (has_exposure or has_time):
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

    # Case 5: Partial metadata without conflicts
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
