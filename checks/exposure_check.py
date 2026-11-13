"""
Forensic check for optical exposure settings (ISO, Aperture, Shutter Speed, Focal Length).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "exposure"
TITLE = "Exposure Information"


def _format_exposure_val(val: Any) -> str:
    """Format numeric or fraction exposure values for human presentation."""
    if val is None:
        return "N/A"
    try:
        # Check if float or fraction
        f = float(val)
        if 0 < f < 1:
            inv = round(1.0 / f)
            return f"1/{inv}s"
        return f"{f:g}s"
    except Exception:
        return str(val)


def _format_fnumber(val: Any) -> str:
    if val is None:
        return "N/A"
    try:
        return f"f/{float(val):g}"
    except Exception:
        return f"f/{val}"


def _format_focal(val: Any) -> str:
    if val is None:
        return "N/A"
    try:
        return f"{float(val):g}mm"
    except Exception:
        return f"{val}mm"


def run(ctx: ImageContext) -> CheckResult:
    """Analyze presence of camera optical capture parameters."""
    iso = ctx.exif.get("ISOSpeedRatings") or ctx.exif.get("PhotographicSensitivity")
    fnumber = ctx.exif.get("FNumber") or ctx.exif.get("ApertureValue")
    exposure_time = ctx.exif.get("ExposureTime") or ctx.exif.get("ShutterSpeedValue")
    focal_length = ctx.exif.get("FocalLength")

    found_params: list[str] = []
    details: dict[str, Any] = {}

    if iso is not None:
        found_params.append(f"ISO {iso}")
        details["iso"] = str(iso)
    if fnumber is not None:
        f_str = _format_fnumber(fnumber)
        found_params.append(f_str)
        details["aperture"] = f_str
    if exposure_time is not None:
        exp_str = _format_exposure_val(exposure_time)
        found_params.append(exp_str)
        details["shutter_speed"] = exp_str
    if focal_length is not None:
        fl_str = _format_focal(focal_length)
        found_params.append(fl_str)
        details["focal_length"] = fl_str

    # If at least 2 optical parameters exist, this is strong evidence of camera optics
    if len(found_params) >= 2:
        evidence = "Optical exposure parameters recorded: " + ", ".join(found_params) + "."
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.0,  # Real-like
            conclusive=True,
            evidence=evidence,
            details=details,
        )

    if len(found_params) == 1:
        evidence = f"Partial exposure parameter recorded: {found_params[0]}. Insufficient for optical verification."
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.4,
            conclusive=False,
            evidence=evidence,
            details=details,
        )

    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=0.5,  # Neutral / Unknown
        conclusive=False,
        evidence="No optical exposure parameters (ISO, aperture, shutter speed, focal length) detected.",
        details={"status": "No exposure metadata"},
    )
