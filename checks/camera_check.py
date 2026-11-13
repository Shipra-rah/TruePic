"""
Forensic check for camera hardware identification (Make and Model).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "camera"
TITLE = "Camera Information"


def run(ctx: ImageContext) -> CheckResult:
    """Inspect camera make and model metadata."""
    make = ctx.exif.get("Make")
    model = ctx.exif.get("Model")
    lens_model = ctx.exif.get("LensModel")

    if make or model:
        make_str = str(make).strip() if make else "Unspecified Make"
        model_str = str(model).strip() if model else "Unspecified Model"

        # Check if make/model is obviously an AI/software placeholder
        combined = f"{make_str} {model_str}".lower()
        if any(x in combined for x in ("stable diffusion", "midjourney", "dall-e", "synthetic")):
            return CheckResult(
                key=KEY,
                title=TITLE,
                found=True,
                signal=1.0,
                conclusive=True,
                evidence=f"Camera fields contain synthetic generator strings: '{make_str} {model_str}'.",
                details={"make": make_str, "model": model_str},
            )

        evidence = f"Physical camera hardware metadata identified: Make '{make_str}', Model '{model_str}'."
        details = {"make": make_str, "model": model_str}
        if lens_model:
            details["lens_model"] = str(lens_model)

        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.0,  # Real-like
            conclusive=True,
            evidence=evidence,
            details=details,
        )

    # Missing camera metadata alone is neutral (rule: not proof of AI)
    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=0.5,  # Neutral / Unknown
        conclusive=False,
        evidence="No camera make or model recorded in EXIF. Common for social media downloads, web graphics, or AI-generated images.",
        details={"status": "Not detected"},
    )
