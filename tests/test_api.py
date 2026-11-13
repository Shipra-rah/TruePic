"""
Integration tests for FastAPI endpoints in main.py.
"""

import io
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["checks_loaded"] == 11


def test_root_serves_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "TruePic" in response.text


def test_template_hello():
    response = client.get("/hello/Forensics")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello Forensics"}


def test_analyze_endpoint_valid_image():
    # Create valid JPEG
    im = Image.new("RGB", (800, 600), color=(50, 100, 150))
    buf = io.BytesIO()
    im.save(buf, format="JPEG")
    buf.seek(0)

    files = {"file": ("test_pic.jpg", buf, "image/jpeg")}
    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200
    data = response.json()

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


def test_analyze_endpoint_empty_file():
    files = {"file": ("empty.jpg", b"", "image/jpeg")}
    response = client.post("/api/analyze", files=files)
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_analyze_endpoint_corrupt_file():
    files = {"file": ("corrupt.jpg", b"NOT_AN_IMAGE_CONTENT_BYTES_123456", "image/jpeg")}
    response = client.post("/api/analyze", files=files)
    assert response.status_code == 400
