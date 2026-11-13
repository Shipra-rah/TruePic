"""
Image context builder for TruePic forensic analysis.
Reads the uploaded image once and constructs a shared, safe inspection context.
"""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass, field
from typing import Any

from PIL import ExifTags, Image, ImageCms

try:
    import c2pa
    HAS_C2PA = True
except Exception:  # pragma: no cover
    c2pa = None
    HAS_C2PA = False


@dataclass
class ImageContext:
    """Shared image context passed to every forensic check module."""

    filename: str
    filesize: int
    raw_bytes: bytes
    sha256: str
    md5: str
    pil_image: Image.Image | None
    format: str  # e.g., 'JPEG', 'PNG', 'WEBP'
    mime_type: str
    width: int
    height: int
    mode: str
    exif: dict[str, Any] = field(default_factory=dict)
    gps: dict[str, Any] = field(default_factory=dict)
    makernote: bytes | None = None
    icc_profile_present: bool = False
    icc_profile_name: str | None = None
    png_text_chunks: dict[str, str] = field(default_factory=dict)
    xmp_raw: str | None = None
    c2pa_manifest: dict[str, Any] | None = None
    c2pa_present: bool = False
    c2pa_error: str | None = None
    warnings: list[str] = field(default_factory=list)


def _safe_decode_str(val: Any) -> str:
    """Convert bytes or other types into clean string representation."""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace").strip("\x00 \t\r\n")
        except Exception:
            return str(val)
    return str(val).strip("\x00 \t\r\n")


def _extract_xmp_from_bytes(data: bytes) -> str | None:
    """Extract raw XMP packet if present in image binary data."""
    # Look for standard <x:xmpmeta ... </x:xmpmeta>
    start_tag = b"<x:xmpmeta"
    end_tag = b"</x:xmpmeta>"
    start_idx = data.find(start_tag)
    if start_idx != -1:
        end_idx = data.find(end_tag, start_idx)
        if end_idx != -1:
            try:
                raw_chunk = data[start_idx : end_idx + len(end_tag)]
                return raw_chunk.decode("utf-8", errors="replace")
            except Exception:
                pass

    # Look for <?xpacket begin ... <?xpacket end
    packet_start = b"<?xpacket begin"
    packet_end = b"<?xpacket end"
    p_start_idx = data.find(packet_start)
    if p_start_idx != -1:
        p_end_idx = data.find(packet_end, p_start_idx)
        if p_end_idx != -1:
            try:
                # include closing tag up to ?>
                closing_gt = data.find(b"?>", p_end_idx)
                if closing_gt != -1:
                    raw_chunk = data[p_start_idx : closing_gt + 2]
                else:
                    raw_chunk = data[p_start_idx : p_end_idx + len(packet_end)]
                return raw_chunk.decode("utf-8", errors="replace")
            except Exception:
                pass

    return None


def _extract_c2pa(data: bytes, mime_type: str) -> tuple[bool, dict[str, Any] | None, str | None]:
    """Attempt C2PA manifest extraction using c2pa-python or signature heuristics."""
    if not HAS_C2PA or c2pa is None:
        # Check raw JUMBF marker
        has_jumb = b"jumb" in data or b"c2pa" in data
        return has_jumb, None, "c2pa library not loaded; fallback marker scan"

    try:
        stream = io.BytesIO(data)
        reader = c2pa.Reader.try_create(format_or_path=mime_type or None, stream=stream)
        if reader is not None:
            try:
                json_str = reader.json()
                import json
                parsed = json.loads(json_str) if json_str else {}
                return True, parsed, None
            except Exception as e:
                return True, None, f"C2PA manifest found but parsing failed: {e}"
        else:
            # try_create returned None -> no C2PA manifest
            return False, None, None
    except Exception as e:
        # Check if JUMBF marker is present in bytes
        has_jumb = b"jumb" in data or b"c2pa" in data
        return has_jumb, None, str(e)


def build_image_context(data: bytes, filename: str) -> ImageContext:
    """Build a complete ImageContext from image bytes and filename."""
    warnings: list[str] = []
    filesize = len(data)

    # Compute hashes
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    # Open image with Pillow
    pil_image: Image.Image | None = None
    img_format = "UNKNOWN"
    mime_type = "application/octet-stream"
    width, height = 0, 0
    mode = "UNKNOWN"
    exif_data: dict[str, Any] = {}
    gps_data: dict[str, Any] = {}
    makernote_bytes: bytes | None = None
    icc_profile_present = False
    icc_profile_name: str | None = None
    png_text_chunks: dict[str, str] = {}
    xmp_raw: str | None = None

    try:
        stream = io.BytesIO(data)
        pil_image = Image.open(stream)
        img_format = pil_image.format or "UNKNOWN"
        mime_type = Image.MIME.get(img_format, "application/octet-stream")
        width, height = pil_image.size
        mode = pil_image.mode

        # Check ICC Profile
        icc_raw = pil_image.info.get("icc_profile")
        if icc_raw:
            icc_profile_present = True
            try:
                profile = ImageCms.getProfileDescription(io.BytesIO(icc_raw))
                icc_profile_name = _safe_decode_str(profile)
            except Exception:
                icc_profile_name = "Embedded ICC Profile (undetermined description)"

        # Check PNG text chunks
        if hasattr(pil_image, "text") and isinstance(pil_image.text, dict):
            for k, v in pil_image.text.items():
                png_text_chunks[_safe_decode_str(k)] = _safe_decode_str(v)

        # Check direct XMP in info
        if "XML:com.adobe.xmp" in pil_image.info:
            val = pil_image.info["XML:com.adobe.xmp"]
            xmp_raw = _safe_decode_str(val)
        elif "xmp" in pil_image.info:
            val = pil_image.info["xmp"]
            xmp_raw = _safe_decode_str(val)

        # Parse EXIF metadata safely
        try:
            raw_exif = pil_image.getexif()
            if raw_exif:
                for tag_id, val in raw_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    exif_data[tag_name] = val

                # Sub-IFD Exif
                try:
                    exif_ifd = raw_exif.get_ifd(ExifTags.IFD.Exif)
                    if exif_ifd:
                        for tag_id, val in exif_ifd.items():
                            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                            # Keep sub-IFD tags, avoid overwriting with empties
                            exif_data[tag_name] = val
                            if tag_name == "MakerNote" or tag_id == 37500:
                                if isinstance(val, (bytes, bytearray)):
                                    makernote_bytes = bytes(val)
                except Exception as e:
                    warnings.append(f"Sub-IFD Exif read note: {e}")

                # Sub-IFD GPS
                try:
                    gps_ifd = raw_exif.get_ifd(ExifTags.IFD.GPSInfo)
                    if gps_ifd:
                        for tag_id, val in gps_ifd.items():
                            tag_name = ExifTags.GPSTAGS.get(tag_id, str(tag_id))
                            gps_data[tag_name] = val
                except Exception as e:
                    warnings.append(f"Sub-IFD GPS read note: {e}")

                # MakerNote IFD check
                try:
                    if not makernote_bytes:
                        mn_ifd = raw_exif.get_ifd(ExifTags.IFD.MakerNote)
                        if mn_ifd:
                            makernote_bytes = b"present"
                except Exception:
                    pass

        except Exception as e:
            warnings.append(f"EXIF parsing warning: {e}")

    except Exception as e:
        warnings.append(f"Pillow image load warning: {e}")

    # Fallback XMP extraction from raw bytes if not found via PIL
    if not xmp_raw:
        xmp_raw = _extract_xmp_from_bytes(data)

    # Check for C2PA manifest
    c2pa_present, c2pa_manifest, c2pa_error = _extract_c2pa(data, mime_type)

    return ImageContext(
        filename=filename,
        filesize=filesize,
        raw_bytes=data,
        sha256=sha256,
        md5=md5,
        pil_image=pil_image,
        format=img_format,
        mime_type=mime_type,
        width=width,
        height=height,
        mode=mode,
        exif=exif_data,
        gps=gps_data,
        makernote=makernote_bytes,
        icc_profile_present=icc_profile_present,
        icc_profile_name=icc_profile_name,
        png_text_chunks=png_text_chunks,
        xmp_raw=xmp_raw,
        c2pa_manifest=c2pa_manifest,
        c2pa_present=c2pa_present,
        c2pa_error=c2pa_error,
        warnings=warnings,
    )
