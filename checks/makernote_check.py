"""
Forensic check for proprietary camera manufacturer MakerNote data blocks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "makernote"
TITLE = "MakerNote"

KNOWN_MAKERNOTE_SIGNATURES = [
    b"Nikon",
    b"FUJIFILM",
    b"Canon",
    b"SONY DSC",
    b"Apple iOS",
    b"OLYMP",
    b"Panasonic",
    b"PENTAX",
]


def run(ctx: ImageContext) -> CheckResult:
    """Detect presence of proprietary camera hardware MakerNote IFD."""
    raw_mn = ctx.makernote

    if raw_mn:
        size = len(raw_mn)
        matched_vendor = "Camera Manufacturer"
        for sig in KNOWN_MAKERNOTE_SIGNATURES:
            if sig in raw_mn[:64]:
                matched_vendor = sig.decode("utf-8", errors="ignore").strip()
                break

        evidence = (
            f"Proprietary {matched_vendor} MakerNote binary structure identified "
            f"({size:,} bytes). Strong indicator of authentic camera firmware capture."
        )

        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.0,  # Real-like
            conclusive=True,
            evidence=evidence,
            details={
                "makernote_present": True,
                "size_bytes": size,
                "vendor_signature": matched_vendor,
            },
        )

    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=0.5,  # Neutral / Unknown
        conclusive=False,
        evidence="No camera manufacturer MakerNote data block detected. Typical of stripped web assets or synthetic imagery.",
        details={"status": "Absent"},
    )
