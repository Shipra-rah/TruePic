"""
Forensic check for GPS geographic location metadata in EXIF.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "gps"
TITLE = "GPS Information"


def _has_camera_provenance(ctx: ImageContext) -> bool:
    """Check whether camera hardware metadata is present."""
    has_make = bool(ctx.exif.get("Make"))
    has_model = bool(ctx.exif.get("Model"))
    return has_make or has_model


def run(ctx: ImageContext) -> CheckResult:
    """Analyze presence of geographic coordinates in GPS IFD."""
    gps = ctx.gps
    has_coords = bool(gps.get("GPSLatitude") and gps.get("GPSLongitude"))

    if has_coords or gps:
        lat = str(gps.get("GPSLatitude", ""))
        lon = str(gps.get("GPSLongitude", ""))
        alt = str(gps.get("GPSAltitude", ""))

        coord_desc = f"Coordinates recorded (Lat: {lat[:15]}..., Lon: {lon[:15]}...)" if has_coords else "GPS tag headers present"
        evidence = (
            f"Physical geographic coordinates detected in EXIF GPS IFD: {coord_desc}. "
            "Strong indicator of mobile device or GPS-equipped physical camera capture."
        )

        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.0,  # Real-like
            conclusive=True,
            evidence=evidence,
            details={
                "has_coordinates": has_coords,
                "gps_tag_count": len(gps),
                "altitude": alt or "Unspecified",
            },
        )

    # Absence of GPS
    has_cam = _has_camera_provenance(ctx)
    if has_cam:
        signal = 0.25
        evidence = "No GPS geolocation coordinates detected. Many digital cameras lack GPS hardware, or users disable location tagging for personal privacy."
    else:
        signal = 0.50
        evidence = "No GPS geolocation coordinates detected. Common for stripped web graphics, privacy-scrubbed photos, and synthetic images."

    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=signal,
        conclusive=False,
        evidence=evidence,
        details={"status": "GPS absent"},
    )
