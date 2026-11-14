"""
Tests for API contracts, schema verification, and core endpoints.
"""

import io
import pytest
from PIL import Image
from core.analyzer import run_analysis
from checks import CHECK_MODULES, CHECK_WEIGHTS


def test_health_contract():
    """Verify that the health check contract matches expectations."""
    assert len(CHECK_MODULES) == 11
    assert sum(CHECK_WEIGHTS.values()) == 100
    assert CHECK_WEIGHTS["sha256"] == 0


def test_analyze_contract_valid_image():
    """Verify analyze pipeline schema on a valid JPEG image."""
    im = Image.new("RGB", (800, 600), color=(50, 100, 150))
    buf = io.BytesIO()
    im.save(buf, format="JPEG")
    buf.seek(0)

    data = run_analysis(buf.getvalue(), "test_pic.jpg")

    assert data["filename"] == "test_pic.jpg"
    assert "sha256" in data
    assert "md5" in data
    assert data["format"] == "JPEG"
    assert data["dimensions"] == "800x600"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "confidence" in data
    assert isinstance(data["checks"], list)
    assert len(data["checks"]) == 11


def test_analyze_contract_empty_file():
    """Verify empty bytes raise ValueError."""
    with pytest.raises(ValueError, match="empty or too small"):
        run_analysis(b"", "empty.jpg")


def test_analyze_contract_corrupt_file():
    """Verify corrupt bytes raise ValueError."""
    with pytest.raises(ValueError, match="Unsupported or unrecognized"):
        run_analysis(b"NOT_AN_IMAGE_CONTENT_BYTES_123456", "corrupt.jpg")
