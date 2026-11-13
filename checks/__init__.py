"""
Central registry of forensic check modules for TruePic.
To add a new forensic check:
1. Create a new check module in `checks/<new_check>.py` exporting KEY, TITLE, and run(ctx).
2. Import and append the module to `CHECK_MODULES`.
3. Define its weight in `CHECK_WEIGHTS`.
"""

from __future__ import annotations

from typing import Any

from checks import (
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
from checks.base import CheckResult

# Registry of check modules in ordered sequence for the forensic table
CHECK_MODULES: list[Any] = [
    sha256_check,
    c2pa_check,
    ai_marker_check,
    camera_check,
    exposure_check,
    resolution_check,
    capture_time_check,
    makernote_check,
    format_check,
    consistency_check,
    gps_check,
]

# Configured forensic weights (sum of weighted checks = 100; sha256 = 0)
CHECK_WEIGHTS: dict[str, int] = {
    sha256_check.KEY: 0,
    c2pa_check.KEY: 25,
    ai_marker_check.KEY: 20,
    camera_check.KEY: 12,
    exposure_check.KEY: 12,
    resolution_check.KEY: 7,
    capture_time_check.KEY: 6,
    makernote_check.KEY: 5,
    format_check.KEY: 5,
    consistency_check.KEY: 5,
    gps_check.KEY: 3,
}

__all__ = [
    "CHECK_MODULES",
    "CHECK_WEIGHTS",
    "CheckResult",
]
