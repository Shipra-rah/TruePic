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

    # Absence of GPS is neutral (common for privacy / web platforms)
    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=0.5,  # Neutral / Unknown
        conclusive=False,
        evidence="No GPS geolocation coordinates detected. Many users and social platforms strip GPS data for personal privacy.",
        details={"status": "GPS absent"},
    )
