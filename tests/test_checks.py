"""
Unit tests for TruePic independent forensic checks and scoring engine.
"""

import io
import pytest
from PIL import ExifTags, Image, PngImagePlugin

from checks import (
    CHECK_MODULES,
    CHECK_WEIGHTS,
    ai_marker_check,
    c2pa_check,
    camera_check,
    capture_time_check,
    consistency_check,
    exposure_check,
    format_check,
    gps_check,
    makernote_check,
    resolution_check,
    sha256_check,
)
from core.context import build_image_context
from core.scoring import calculate_risk


def create_test_image(
    format="JPEG",
    size=(1024, 1024),
    color=(100, 150, 200),
    exif_tags=None,
    png_text=None,
) -> bytes:
    """Helper to generate in-memory test images with controlled metadata."""
    im = Image.new("RGB", size, color=color)
    buf = io.BytesIO()

    exif_obj = None
    if exif_tags:
        exif_obj = im.getexif()
        for k, v in exif_tags.get("root", {}).items():
            exif_obj[k] = v
        if "exif_ifd" in exif_tags:
            sub = exif_obj.get_ifd(ExifTags.IFD.Exif)
            for k, v in exif_tags["exif_ifd"].items():
                sub[k] = v
        if "gps_ifd" in exif_tags:
            sub = exif_obj.get_ifd(ExifTags.IFD.GPSInfo)
            for k, v in exif_tags["gps_ifd"].items():
                sub[k] = v

    png_info = None
    if png_text and format.upper() == "PNG":
        png_info = PngImagePlugin.PngInfo()
        for k, v in png_text.items():
            png_info.add_text(k, v)

    kwargs = {"format": format}
    if exif_obj:
        kwargs["exif"] = exif_obj
    if png_info:
        kwargs["pnginfo"] = png_info

    im.save(buf, **kwargs)
    return buf.getvalue()


def test_registry_consistency():
    """Verify registry has exactly 11 checks totaling 100 points."""
    assert len(CHECK_MODULES) == 11
    assert len(CHECK_WEIGHTS) == 11
    assert CHECK_WEIGHTS["sha256"] == 0
    weighted_sum = sum(w for k, w in CHECK_WEIGHTS.items() if k != "sha256")
    assert weighted_sum == 100


def test_sha256_check():
    data = create_test_image()
    ctx = build_image_context(data, "sample.jpg")
    res = sha256_check.run(ctx)
    assert res.key == "sha256"
    assert res.found is True
    assert res.conclusive is True
    assert ctx.sha256 in res.evidence


def test_ai_marker_check_with_diffusion_parameters():
    data = create_test_image(
        format="PNG",
        png_text={"parameters": "cyberpunk portrait, steps: 25, sampler: DPM++ 2M Karras, cfg scale: 7, seed: 999"},
    )
    ctx = build_image_context(data, "ai.png")
    res = ai_marker_check.run(ctx)
    assert res.found is True
    assert res.signal == 1.0
    assert res.conclusive is True
    assert "parameters" in res.evidence


def test_camera_and_exposure_check_authentic():
    data = create_test_image(
        format="JPEG",
        size=(4032, 3024),
        exif_tags={
            "root": {
                ExifTags.Base.Make: "Sony",
                ExifTags.Base.Model: "ILCE-7M4",
            },
            "exif_ifd": {
                ExifTags.Base.DateTimeOriginal: "2024:06:10 14:00:00",
                ExifTags.Base.ExposureTime: 0.002,
                ExifTags.Base.FNumber: 2.8,
                ExifTags.Base.ISOSpeedRatings: 200,
                ExifTags.Base.FocalLength: 50.0,
                ExifTags.Base.MakerNote: b"SONY DSC camera firmware data block",
            },
            "gps_ifd": {
                ExifTags.GPS.GPSLatitude: (37, 46, 29),
                ExifTags.GPS.GPSLongitude: (122, 25, 9),
            },
        },
    )
    ctx = build_image_context(data, "camera_photo.jpg")

    cam_res = camera_check.run(ctx)
    assert cam_res.found is True
    assert cam_res.signal == 0.0
    assert cam_res.conclusive is True

    exp_res = exposure_check.run(ctx)
    assert exp_res.found is True
    assert exp_res.signal == 0.0
    assert exp_res.conclusive is True

    cap_res = capture_time_check.run(ctx)
    assert cap_res.found is True
    assert cap_res.signal == 0.0

    mn_res = makernote_check.run(ctx)
    assert mn_res.found is True
    assert mn_res.signal == 0.0

    gps_res = gps_check.run(ctx)
    assert gps_res.found is True
    assert gps_res.signal == 0.0


def test_resolution_check_generative_pattern():
    data = create_test_image(size=(1024, 1024))
    ctx = build_image_context(data, "square.jpg")
    res = resolution_check.run(ctx)
    assert res.found is True
    assert res.signal >= 0.8
    assert "SDXL" in res.evidence or "1024x1024" in res.evidence


def test_format_check_mismatch_anomaly():
    # PNG bytes with .jpg extension
    data = create_test_image(format="PNG")
    ctx = build_image_context(data, "fake_jpeg.jpg")
    res = format_check.run(ctx)
    assert res.found is True
    assert res.signal == 0.85
    assert "mismatch" in res.evidence.lower()


def test_scoring_ai_override():
    # Construct results with explicit AI marker
    from checks.base import CheckResult
    dummy_results = [
        CheckResult(key="sha256", title="SHA-256", found=True, signal=0.5, conclusive=True, evidence="hash"),
        CheckResult(key="c2pa", title="C2PA", found=False, signal=0.5, conclusive=False, evidence="none"),
        CheckResult(key="ai_markers", title="AI", found=True, signal=1.0, conclusive=True, evidence="prompt"),
        CheckResult(key="camera", title="Camera", found=False, signal=0.5, conclusive=False, evidence="none"),
    ]
    scoring = calculate_risk(dummy_results, CHECK_WEIGHTS)
    assert scoring["risk_score"] >= 90
    assert scoring["risk_level"] == "Very High"
    assert scoring["override_applied"] is True


def test_real_camera_full_pipeline_score():
    """Verify real camera image outputs 10 to 20 with High confidence."""
    from core.analyzer import run_analysis
    data = create_test_image(
        format="JPEG",
        size=(4032, 3024),
        exif_tags={
            "root": {
                ExifTags.Base.Make: "Apple",
                ExifTags.Base.Model: "iPhone 15 Pro",
            },
            "exif_ifd": {
                ExifTags.Base.DateTimeOriginal: "2024:06:10 14:00:00",
                ExifTags.Base.ExposureTime: 0.002,
                ExifTags.Base.FNumber: 1.78,
                ExifTags.Base.ISOSpeedRatings: 100,
                ExifTags.Base.FocalLength: 6.86,
                ExifTags.Base.MakerNote: b"Apple iOS data block",
            },
            "gps_ifd": {
                ExifTags.GPS.GPSLatitude: (37, 46, 29),
                ExifTags.GPS.GPSLongitude: (122, 25, 9),
            },
        },
    )
    analysis = run_analysis(data, "iphone_photo.jpg")
    # Requirement 1: Camera image output 10 to 20
    assert 10 <= analysis["risk_score"] <= 20
    assert analysis["risk_level"] == "Low"
    # Requirement 2: High confidence for real image
    assert analysis["confidence"] == "High"
    assert analysis["confidence_percentage"] >= 70.0


def test_ai_generated_image_high_confidence():
    """Verify AI image outputs 90 to 99 with High confidence (not 20-25%)."""
    from core.analyzer import run_analysis
    data = create_test_image(
        format="PNG",
        size=(1024, 1024),
        png_text={
            "parameters": "photorealistic portrait, 8k\nSteps: 25, Sampler: Euler a, CFG scale: 7, Seed: 987654321, Size: 1024x1024"
        },
    )
    analysis = run_analysis(data, "diffusion_art.png")
    # Requirement 3: AI output near 90 to 99
    assert 90 <= analysis["risk_score"] <= 99
    assert analysis["risk_level"] == "Very High"
    # Requirement 3: Confidence should be HIGH, not 20-25%
    assert analysis["confidence"] == "High"
    assert analysis["confidence_percentage"] >= 70.0


def test_stripped_image_inconclusive():
    """Verify stripped/social-media image is Inconclusive (~45-55) with Low confidence."""
    from core.analyzer import run_analysis
    data = create_test_image(format="JPEG", size=(1080, 1080))
    analysis = run_analysis(data, "stripped_upload.jpg")
    assert 40 <= analysis["risk_score"] <= 60
    assert analysis["risk_level"] == "Inconclusive"
    assert analysis["confidence"] == "Low"

