"""
Forensic check for cryptographic file integrity hashes (SHA-256 and MD5).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from checks.base import CheckResult

if TYPE_CHECKING:
    from core.context import ImageContext

KEY = "sha256"
TITLE = "SHA-256 / MD5"


def run(ctx: ImageContext) -> CheckResult:
    """Evaluate cryptographic file hashes for integrity tracking."""
    sha256 = ctx.sha256
    md5 = ctx.md5
    filesize = ctx.filesize

    evidence = (
        f"SHA-256: {sha256} | MD5: {md5} "
        f"({filesize:,} bytes). Informational hash for chain-of-custody verification."
    )

    return CheckResult(
        key=KEY,
        title=TITLE,
        found=True,
        signal=0.5,  # Neutral/Informational
        conclusive=True,
        evidence=evidence,
        details={
            "sha256": sha256,
            "md5": md5,
            "filesize_bytes": filesize,
            "role": "Informational / Chain of Custody",
        },
    )
