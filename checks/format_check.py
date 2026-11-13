"""
Forensic check for image format integrity, container headers, and ICC color profile.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "format"
TITLE = "Image Format"

EXT_FORMAT_MAP = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".jpe": "JPEG",
    ".png": "PNG",
    ".webp": "WEBP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
    ".bmp": "BMP",
}


def run(ctx: ImageContext) -> CheckResult:
    """Analyze file container format, extension consistency, and ICC profile."""
    _, ext = os.path.splitext(ctx.filename.lower())
    expected_format = EXT_FORMAT_MAP.get(ext)
    actual_format = ctx.format.upper()

    details = {
        "detected_format": actual_format,
        "file_extension": ext or "none",
        "mime_type": ctx.mime_type,
        "color_mode": ctx.mode,
        "icc_profile_present": ctx.icc_profile_present,
    }

    # 1. Check for disguised or conflicting extension
    if expected_format and expected_format != actual_format:
        evidence = (
            f"Extension mismatch: File extension '{ext}' does not match detected container "
            f"format '{actual_format}'. Potential file disguising or re-encoding anomaly."
        )
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.85,  # Anomaly signal
            conclusive=True,
            evidence=evidence,
            details=details,
        )

    # 2. Check ICC profile
    icc_info = ""
    if ctx.icc_profile_present:
        icc_name = ctx.icc_profile_name or "Embedded ICC Profile"
        details["icc_profile_name"] = icc_name
        icc_info = f" Embedded ICC profile: '{icc_name}'."
    else:
        icc_info = " No embedded ICC color profile."

    evidence = (
        f"Format verified: Valid {actual_format} container matching '{ext}' extension.{icc_info}"
    )

    # Images with camera-typical Display P3 or Adobe RGB profiles skew slightly real-like
    signal = 0.1 if (ctx.icc_profile_present and "display p3" in str(ctx.icc_profile_name).lower()) else 0.3

    return CheckResult(
        key=KEY,
        title=TITLE,
        found=True,
        signal=signal,
        conclusive=False,
        evidence=evidence,
        details=details,
    )
