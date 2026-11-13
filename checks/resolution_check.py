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
    (4032, 3024): "Standard 12MP Smartphone Sensor (4:3)",
    (3024, 4032): "Standard 12MP Smartphone Sensor (Portrait)",
    (4000, 3000): "Standard 12MP Digital Camera (4:3)",
    (3000, 4000): "Standard 12MP Digital Camera (Portrait)",
    (6000, 4000): "Standard 24MP APS-C / Full-Frame DSLR/Mirrorless (3:2)",
    (4000, 6000): "Standard 24MP APS-C / Full-Frame DSLR/Mirrorless (Portrait)",
    (8064, 6048): "High-Resolution 48MP Quad-Bayer Sensor",
    (6048, 8064): "High-Resolution 48MP Quad-Bayer Sensor (Portrait)",
    (3264, 2448): "Standard 8MP Camera Sensor",
}


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
            signal=0.1,  # Real-like
            conclusive=False,
            evidence=evidence,
            details={
                "dimensions": f"{w}x{h}",
                "megapixels": mp,
                "aspect_ratio": aspect_ratio,
                "matched_pattern": cam_desc,
            },
        )

    # 3. Check for exact square power of 2 or 64-multiple commonly used in generation
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

    evidence = f"Dimensions {w}x{h} ({mp} MP, aspect ratio {aspect_ratio}). Non-standard custom resolution."
    return CheckResult(
        key=KEY,
        title=TITLE,
        found=True,
        signal=0.5,  # Neutral
        conclusive=False,
        evidence=evidence,
        details={
            "dimensions": f"{w}x{h}",
            "megapixels": mp,
            "aspect_ratio": aspect_ratio,
        },
    )
