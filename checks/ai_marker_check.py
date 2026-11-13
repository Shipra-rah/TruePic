"""
Forensic check for AI generation metadata markers and prompts.
Inspects PNG chunks, EXIF Software/UserComment, XMP packets, and IPTC DigitalSourceType.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "ai_markers"
TITLE = "AI Markers"

# Common AI generator signatures and parameter tokens
AI_SOFTWARE_SIGNATURES = [
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
]

# Standard IPTC AI media indicator URI
IPTC_ALGORITHMIC_URI = "digitalsourcetype/trainedalgorithmicmedia"

# Diffusion parameter patterns
DIFFUSION_PARAM_PATTERNS = [
    r"steps:\s*\d+",
    r"sampler:\s*[\w\+]+",
    r"cfg scale:\s*[\d\.]+",
    r"seed:\s*\d+",
    r"negative prompt:",
    r"denoising strength:\s*[\d\.]+",
]


def run(ctx: ImageContext) -> CheckResult:
    """Scan all metadata channels for explicit AI generation markers."""
    detected_markers: list[str] = []
    details: dict[str, str] = {}

    # 1. Check PNG text chunks
    for key, val in ctx.png_text_chunks.items():
        k_lower = key.lower()
        v_lower = val.lower()

        # ComfyUI workflow/prompt chunks
        if k_lower in ("prompt", "workflow") and any(x in v_lower for x in ("class_type", "ksampler", "checkpointloadersimple")):
            marker = f"PNG '{key}' chunk contains ComfyUI node graph"
            detected_markers.append(marker)
            details["png_comfyui"] = val[:200]

        # Automatic1111 parameters chunk
        if k_lower == "parameters":
            marker = "PNG 'parameters' chunk containing diffusion generation settings"
            detected_markers.append(marker)
            details["png_parameters"] = val[:200]

        # General software mention
        for sig in AI_SOFTWARE_SIGNATURES:
            if sig in v_lower:
                marker = f"PNG '{key}' chunk references AI generator '{sig}'"
                detected_markers.append(marker)
                details[f"png_{sig}"] = val[:200]

    # 2. Check EXIF Software and UserComment
    exif_software = str(ctx.exif.get("Software", "")).lower()
    for sig in AI_SOFTWARE_SIGNATURES:
        if sig in exif_software:
            marker = f"EXIF Software field specifies '{ctx.exif.get('Software')}'"
            detected_markers.append(marker)
            details["exif_software"] = str(ctx.exif.get("Software"))

    exif_comment = str(ctx.exif.get("UserComment", "")).lower()
    if exif_comment:
        for pattern in DIFFUSION_PARAM_PATTERNS:
            if re.search(pattern, exif_comment):
                marker = f"EXIF UserComment contains diffusion generation parameter '{pattern}'"
                detected_markers.append(marker)
                details["exif_comment_pattern"] = exif_comment[:200]
                break

    # 3. Check XMP metadata
    if ctx.xmp_raw:
        xmp_lower = ctx.xmp_raw.lower()
        if IPTC_ALGORITHMIC_URI in xmp_lower:
            marker = "XMP contains official IPTC DigitalSourceType 'trainedAlgorithmicMedia'"
            detected_markers.append(marker)
            details["xmp_iptc_source"] = "trainedAlgorithmicMedia"

        for sig in AI_SOFTWARE_SIGNATURES:
            if sig in xmp_lower:
                marker = f"XMP metadata references AI engine '{sig}'"
                detected_markers.append(marker)
                details[f"xmp_{sig}"] = "Found in XMP payload"

    if detected_markers:
        evidence = "Explicit AI markers found: " + "; ".join(detected_markers[:2])
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=1.0,  # AI-like
            conclusive=True,
            evidence=evidence,
            details=details,
        )

    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=0.5,  # Neutral/Unknown: absence does not guarantee it wasn't stripped
        conclusive=False,
        evidence="No AI generation signatures, diffusion parameters, or IPTC algorithmic media markers detected.",
        details={"status": "No markers found"},
    )
