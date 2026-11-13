"""
Forensic check for original capture timestamps (DateTimeOriginal, SubSecTimeOriginal, OffsetTime).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "capture_time"
TITLE = "Capture Time"


def run(ctx: ImageContext) -> CheckResult:
    """Inspect camera sensor capture timestamp integrity."""
    dto = ctx.exif.get("DateTimeOriginal")
    subsec = ctx.exif.get("SubSecTimeOriginal") or ctx.exif.get("SubSecTime")
    offset = ctx.exif.get("OffsetTimeOriginal") or ctx.exif.get("OffsetTime")
    dtd = ctx.exif.get("DateTimeDigitized")
    dt = ctx.exif.get("DateTime")

    if dto:
        dto_str = str(dto).strip()
        timestamp_full = dto_str
        if subsec:
            timestamp_full += f".{subsec}"
        if offset:
            timestamp_full += f" (UTC{offset})"

        evidence = f"Original capture timestamp present: {timestamp_full}."
        details = {
            "datetime_original": dto_str,
            "subsec_precision": str(subsec) if subsec else "None",
            "timezone_offset": str(offset) if offset else "None",
        }

        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.0,  # Real-like
            conclusive=True,
            evidence=evidence,
            details=details,
        )

    if dt or dtd:
        fallback_dt = str(dt or dtd).strip()
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.4,
            conclusive=False,
            evidence=f"Generic timestamp present ({fallback_dt}), but original sensor capture timestamp (DateTimeOriginal) is missing.",
            details={"datetime_generic": fallback_dt},
        )

    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=0.5,  # Neutral / Unknown
        conclusive=False,
        evidence="No original capture timestamp (DateTimeOriginal) recorded in metadata.",
        details={"status": "Timestamp absent"},
    )
