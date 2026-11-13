"""
Central forensic analyzer for TruePic.
Coordinates the execution of all registered check modules and compiles the final report.
"""

from __future__ import annotations

import io
from typing import Any
from PIL import Image

from checks import CHECK_MODULES, CHECK_WEIGHTS, CheckResult
from core.context import ImageContext, build_image_context
from core.scoring import calculate_risk

# Magic byte signatures for common image containers
VALID_IMAGE_SIGNATURES = [
    b"\xff\xd8\xff",  # JPEG
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"RIFF",  # WEBP (starts with RIFF....WEBP)
    b"II*\x00",  # TIFF little-endian
    b"MM\x00*",  # TIFF big-endian
    b"GIF87a",  # GIF
    b"GIF89a",
    b"BM",  # BMP
]


def _validate_image_bytes(data: bytes, filename: str) -> None:
    """Validate that uploaded bytes represent a supported, non-corrupt image."""
    if not data or len(data) < 16:
        raise ValueError("Uploaded file is empty or too small to be a valid image.")

    # Check magic bytes
    has_valid_signature = False
    for sig in VALID_IMAGE_SIGNATURES:
        if data.startswith(sig):
            if sig == b"RIFF" and len(data) >= 12 and data[8:12] != b"WEBP":
                continue
            has_valid_signature = True
            break

    if not has_valid_signature:
        raise ValueError(
            "Unsupported or unrecognized file format. Uploaded file does not have a recognized image signature."
        )

    # Validate PIL can open and read headers
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
    except Exception as e:
        raise ValueError(f"Corrupt or unreadable image stream: {e}") from e


def run_analysis(data: bytes, filename: str) -> dict[str, Any]:
    """Execute complete forensic analysis pipeline on the uploaded image.

    Args:
        data: Raw binary bytes of the image file.
        filename: Original name of the uploaded file.

    Returns:
        Structured JSON dictionary containing file integrity hashes,
        forensic checks table data, risk scoring, confidence, and explanations.
    """
    # 1. Validate image format and bytes
    _validate_image_bytes(data, filename)

    # 2. Build shared context once
    ctx: ImageContext = build_image_context(data, filename)

    # 3. Execute all registered checks with safety guards
    check_results: list[CheckResult] = []
    for module in CHECK_MODULES:
        key = getattr(module, "KEY", "unknown")
        title = getattr(module, "TITLE", "Unknown Check")
        try:
            res: CheckResult = module.run(ctx)
            check_results.append(res)
        except Exception as e:
            # Prevent one failing check from crashing entire pipeline
            ctx.warnings.append(f"Check '{key}' failed with error: {e}")
            check_results.append(
                CheckResult(
                    key=key,
                    title=title,
                    found=None,
                    signal=0.5,
                    conclusive=False,
                    evidence=f"Forensic check failed during execution: {e}",
                    details={"error": str(e)},
                    skipped=True,
                )
            )

    # 4. Calculate score and metrics
    scoring_data = calculate_risk(check_results, CHECK_WEIGHTS)

    # 5. Format results into structured dictionary matching required schema
    checks_list: list[dict[str, Any]] = []
    for res in check_results:
        weight = CHECK_WEIGHTS.get(res.key, 0)
        # Points = weight * signal (informational or skipped = 0)
        if weight == 0 or res.skipped:
            points: float | int = 0
        else:
            calc_pts = round(weight * res.signal, 1)
            points = int(calc_pts) if calc_pts.is_integer() else calc_pts

        checks_list.append(
            {
                "key": res.key,
                "title": res.title,
                "found": res.found,
                "signal": res.signal,
                "weight": weight,
                "points": points,
                "conclusive": res.conclusive,
                "skipped": res.skipped,
                "evidence": res.evidence,
                "details": res.details,
            }
        )

    dimensions_str = f"{ctx.width}x{ctx.height}" if ctx.width and ctx.height else "Unknown"

    return {
        "filename": ctx.filename,
        "filesize": ctx.filesize,
        "sha256": ctx.sha256,
        "md5": ctx.md5,
        "dimensions": dimensions_str,
        "format": ctx.format,
        "mime_type": ctx.mime_type,
        "risk_score": scoring_data["risk_score"],
        "risk_level": scoring_data["risk_level"],
        "confidence": scoring_data["confidence"],
        "confidence_percentage": scoring_data["confidence_percentage"],
        "explanation": scoring_data["explanation"],
        "override_applied": scoring_data["override_applied"],
        "override_reason": scoring_data["override_reason"],
        "checks": checks_list,
        "warnings": ctx.warnings,
    }
