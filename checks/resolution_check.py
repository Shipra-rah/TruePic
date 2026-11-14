"""
Forensic check for resolution and dimension patterns characteristic of generative AI models.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "resolution"
TITLE = "Resolution Analysis"

# Canonical latent diffusion & transformer generative model training resolutions
AI_TRAINING_RESOLUTIONS = {
    (512, 512): "Stable Diffusion 1.5 standard base resolution",
    (768, 768): "Stable Diffusion 2.0 / 2.1 base resolution",
    (1024, 1024): "SDXL / DALL-E 3 / Midjourney v5/v6 canonical 1:1 resolution",
    (1152, 896): "SDXL native bucket (approx 9:7)",
    (896, 1152): "SDXL native portrait bucket (approx 7:9)",
    (1216, 832): "SDXL native widescreen bucket (approx 3:2)",
    (832, 1216): "SDXL native tall bucket (approx 2:3)",
    (1344, 768): "SDXL native cinematic bucket (approx 7:4)",
    (768, 1344): "SDXL native vertical bucket (approx 4:7)",
    (1536, 640): "SDXL native ultra-wide bucket",
    (640, 1536): "SDXL native ultra-tall bucket",
    (1024, 1792): "DALL-E 3 vertical default",
    (1792, 1024): "DALL-E 3 landscape default",
    (1024, 1536): "Midjourney v6 2:3 portrait default",
    (1536, 1024): "Midjourney v6 3:2 landscape default",
}

# Common physical camera sensor resolutions (width, height)
CAMERA_SENSOR_RESOLUTIONS = {
    # 12MP Mobile / Compact
    (4032, 3024): "Standard 12MP Smartphone Sensor (4:3)",
    (3024, 4032): "Standard 12MP Smartphone Sensor (Portrait)",
    (4000, 3000): "Standard 12MP Digital Camera (4:3)",
    (3000, 4000): "Standard 12MP Digital Camera (Portrait)",
    # 24MP DSLR / Mirrorless / Mobile
    (6000, 4000): "Standard 24MP APS-C / Full-Frame DSLR/Mirrorless (3:2)",
    (4000, 6000): "Standard 24MP APS-C / Full-Frame DSLR/Mirrorless (Portrait)",
    (5712, 4284): "Standard 24MP Smartphone Sensor (4:3)",
    (4284, 5712): "Standard 24MP Smartphone Sensor (Portrait)",
    # 30MP - 36MP Full-Frame DSLR
    (6720, 4480): "30MP Full-Frame DSLR Sensor (Canon 5D Mk IV 3:2)",
    (4480, 6720): "30MP Full-Frame DSLR Sensor (Portrait)",
    (7360, 4912): "36MP Full-Frame DSLR Sensor (Nikon D800/D810 3:2)",
    (4912, 7360): "36MP Full-Frame DSLR Sensor (Portrait)",
    # 20MP / 18MP / 16MP Cameras
    (5472, 3648): "20MP 1-inch / Micro 4/3 Sensor (3:2)",
    (3648, 5472): "20MP 1-inch / Micro 4/3 Sensor (Portrait)",
    (5184, 3888): "20MP Micro 4/3 Sensor (4:3)",
    (3888, 5184): "20MP Micro 4/3 Sensor (Portrait)",
    (5184, 3456): "18MP APS-C DSLR Sensor (Canon EOS 3:2)",
    (3456, 5184): "18MP APS-C DSLR Sensor (Portrait)",
    (4608, 3456): "16MP Micro Four Thirds / Compact Sensor (4:3)",
    (3456, 4608): "16MP Micro Four Thirds / Compact Sensor (Portrait)",
    # 48MP - 108MP Quad-Bayer High-Res Mobile
    (8064, 6048): "High-Resolution 48MP Quad-Bayer Sensor",
    (6048, 8064): "High-Resolution 48MP Quad-Bayer Sensor (Portrait)",
    (8000, 6000): "High-Resolution 48MP Sensor (4:3)",
    (6000, 8000): "High-Resolution 48MP Sensor (Portrait)",
    (9248, 6936): "High-Resolution 64MP Quad-Bayer Sensor",
    (6936, 9248): "High-Resolution 64MP Quad-Bayer Sensor (Portrait)",
    (12000, 9000): "High-Resolution 108MP Sensor",
    (9000, 12000): "High-Resolution 108MP Sensor (Portrait)",
    # 8MP / Standard Video
    (3264, 2448): "Standard 8MP Camera Sensor",
    (2448, 3264): "Standard 8MP Camera Sensor (Portrait)",
    (3840, 2160): "4K UHD 16:9 Standard Capture",
    (2160, 3840): "4K UHD 16:9 Portrait Capture",
    (1920, 1080): "1080p FHD 16:9 Standard Capture",
    (1080, 1920): "1080p FHD 16:9 Portrait Capture",
}


def _has_camera_provenance(ctx: ImageContext) -> bool:
    """Check whether the image has physical camera metadata indicators."""
    has_make = bool(ctx.exif.get("Make"))
    has_model = bool(ctx.exif.get("Model"))
    has_exposure = any(k in ctx.exif for k in ("ExposureTime", "FNumber", "ISOSpeedRatings"))
    has_time = bool(ctx.exif.get("DateTimeOriginal"))
    return (has_make or has_model) and (has_exposure or has_time)


def run(ctx: ImageContext) -> CheckResult:
    """Analyze image dimensions for AI generator signatures vs camera sensor aspect ratios."""
    w, h = ctx.width, ctx.height
    if w <= 0 or h <= 0:
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=False,
            signal=0.5,
            conclusive=False,
            evidence="Unable to determine image resolution.",
            details={},
        )

    mp = round((w * h) / 1_000_000, 2)
    gcd = math.gcd(w, h)
    aspect_ratio = f"{w // gcd}:{h // gcd}" if gcd > 0 else f"{w}:{h}"
    has_cam = _has_camera_provenance(ctx)

    # 1. Exact match with canonical AI generative resolutions
    if (w, h) in AI_TRAINING_RESOLUTIONS:
        model_desc = AI_TRAINING_RESOLUTIONS[(w, h)]
        evidence = (
            f"Dimensions {w}x{h} ({mp} MP, {aspect_ratio}) exactly match {model_desc}."
        )
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.85,  # Strong AI-correlated signal
            conclusive=True,
            evidence=evidence,
            details={
                "dimensions": f"{w}x{h}",
                "megapixels": mp,
                "aspect_ratio": aspect_ratio,
                "matched_pattern": model_desc,
            },
        )

    # 2. Check for standard camera sensor resolution
    if (w, h) in CAMERA_SENSOR_RESOLUTIONS:
        cam_desc = CAMERA_SENSOR_RESOLUTIONS[(w, h)]
        evidence = f"Dimensions {w}x{h} ({mp} MP) match {cam_desc}."
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.15,  # Real-like
            conclusive=True if has_cam else False,
            evidence=evidence,
            details={
                "dimensions": f"{w}x{h}",
                "megapixels": mp,
                "aspect_ratio": aspect_ratio,
                "matched_pattern": cam_desc,
            },
        )

    # 3. Check for standard camera aspect ratio (4:3, 3:2, 16:9) with realistic sensor megapixel count
    ratio = max(w, h) / min(w, h) if min(w, h) > 0 else 0
    is_cam_ratio = any(abs(ratio - r) < 0.03 for r in (4/3, 3/2, 16/9))
    if is_cam_ratio and mp >= 2.0 and has_cam:
        evidence = (
            f"Dimensions {w}x{h} ({mp} MP) follow standard camera sensor aspect ratio "
            f"({aspect_ratio}) matching optical hardware capture."
        )
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.15,  # Real-like
            conclusive=True,
            evidence=evidence,
            details={
                "dimensions": f"{w}x{h}",
                "megapixels": mp,
                "aspect_ratio": aspect_ratio,
                "matched_pattern": "Standard Camera Aspect Ratio",
            },
        )

    # 4. Check for exact square power of 2 or 64-multiple commonly used in generation
    if w == h and (w % 64 == 0) and w in (256, 384, 512, 640, 768, 896, 1024, 1280, 1536, 2048):
        evidence = f"Dimensions {w}x{h} (1:1 square, divisible by 64) follow standard AI latent canvas conventions."
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.75,
            conclusive=False,
            evidence=evidence,
            details={
                "dimensions": f"{w}x{h}",
                "megapixels": mp,
                "aspect_ratio": "1:1",
                "matched_pattern": "Square divisible by 64",
            },
        )

    evidence = f"Dimensions {w}x{h} ({mp} MP, aspect ratio {aspect_ratio}). Custom or cropped resolution."
    return CheckResult(
        key=KEY,
        title=TITLE,
        found=True,
        signal=0.45 if has_cam else 0.50,
        conclusive=False,
        evidence=evidence,
        details={
            "dimensions": f"{w}x{h}",
            "megapixels": mp,
            "aspect_ratio": aspect_ratio,
        },
    )
