"""
Forensic check for C2PA (Coalition for Content Provenance and Authenticity) Content Credentials.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "c2pa"
TITLE = "C2PA Credentials"

AI_KEYWORDS = {
    "trainedalgorithmicmedia",
    "algorithmicmedia",
    "ai_generated",
    "firefly",
    "midjourney",
    "dall-e",
    "chatgpt",
    "openai",
    "stable diffusion",
    "stablediffusion",
    "novelai",
    "generative",
    "synthetic",
}


def _inspect_manifest(manifest: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
    """Inspect manifest structure to detect if content was declared as AI-generated."""
    manifest_str = json.dumps(manifest).lower()
    claim_generator = ""
    title = ""

    # Check active manifest if provided
    active_manifest_id = manifest.get("active_manifest")
    manifests = manifest.get("manifests", {})
    target = manifests.get(active_manifest_id, manifest) if active_manifest_id else manifest

    if isinstance(target, dict):
        claim_generator = str(target.get("claim_generator", ""))
        title = str(target.get("title", ""))

    for kw in AI_KEYWORDS:
        if kw in manifest_str:
            return (
                True,
                f"C2PA Content Credentials manifest found with explicit AI generation declaration (matched '{kw}').",
                {
                    "declared_ai": True,
                    "claim_generator": claim_generator,
                    "title": title,
                    "matched_indicator": kw,
                },
            )

    return (
        False,
        f"Valid C2PA Content Credentials manifest detected (Generator: '{claim_generator or 'Standard'}').",
        {
            "declared_ai": False,
            "claim_generator": claim_generator,
            "title": title,
        },
    )


def run(ctx: ImageContext) -> CheckResult:
    """Evaluate C2PA provenance credentials and manifest assertions."""
    # If a full parsed manifest exists
    if ctx.c2pa_manifest:
        is_ai, evidence_msg, meta = _inspect_manifest(ctx.c2pa_manifest)
        if is_ai:
            return CheckResult(
                key=KEY,
                title=TITLE,
                found=True,
                signal=1.0,  # AI-like
                conclusive=True,
                evidence=evidence_msg,
                details={
                    "status": "Verified AI Manifest",
                    **meta,
                },
            )
        else:
            return CheckResult(
                key=KEY,
                title=TITLE,
                found=True,
                signal=0.0,  # Real-like provenance
                conclusive=True,
                evidence=evidence_msg,
                details={
                    "status": "Verified Authentic Manifest",
                    **meta,
                },
            )

    # If raw JUMBF marker was detected but parser was unavailable or failed
    if ctx.c2pa_present:
        return CheckResult(
            key=KEY,
            title=TITLE,
            found=True,
            signal=0.5,
            conclusive=False,
            evidence="C2PA JUMBF container marker detected in bytes, but manifest validation could not be completed.",
            details={
                "status": "Marker Present / Unverified",
                "error": ctx.c2pa_error,
            },
        )

    # Normal case: No C2PA credentials found
    return CheckResult(
        key=KEY,
        title=TITLE,
        found=False,
        signal=0.5,  # Neutral: Missing C2PA is NOT proof of AI
        conclusive=False,
        evidence="No C2PA Content Credentials manifest detected. A missing manifest is common for camera captures and legacy digital images.",
        details={
            "status": "Not Found",
            "c2pa_available": True,
        },
    )
