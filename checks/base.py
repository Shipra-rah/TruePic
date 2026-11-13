"""
Base definitions and shared data structures for TruePic forensic checks.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CheckResult:
    """Standardized result returned by every forensic check module.

    Attributes:
        key: Unique machine-readable identifier for the check (e.g., 'camera').
        title: Human-readable row name in the forensic table.
        found: True if the target metadata/marker was detected, False if searched
            and confirmed absent, or None if unknown/indeterminate.
        signal: Heuristic signal where 0.0 = Real-like, 0.5 = Neutral/Unknown,
            1.0 = AI-like evidence.
        conclusive: True if this check provides strong, definitive evidence for
            its signal rating.
        evidence: Human-readable sentence explaining the forensic conclusion.
        details: Additional structured forensic key-value pairs for deep inspection.
        skipped: True if this check could not be performed or was bypassed.
        image_path: Optional path reference to the analyzed image.
    """

    key: str
    title: str
    found: bool | None
    signal: float
    conclusive: bool
    evidence: str
    details: dict[str, Any] = field(default_factory=dict)
    skipped: bool = False
    image_path: str | None = None
