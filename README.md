# TruePic — Image Authenticity & Forensics Assistant

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Pillow](https://img.shields.io/badge/Pillow-Image%20Forensics-yellow.svg)](https://python-pillow.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**TruePic** is a lightweight, explainable image authenticity and digital forensics web application. Built with **FastAPI**, **Pillow**, and **Vanilla JavaScript**, it performs multi-factor heuristic checks to identify generative AI markers, digital manipulation, and genuine physical camera provenance without relying on opaque deep-learning models.

---

## Key Features

- **Modular Heuristic Engine**: 11 independent check modules—each check is isolated in its own file and never crashes the pipeline.
- **In-Memory Non-Destructive Pipeline**: Images are parsed once in memory into a shared context without saving or altering uploaded files.
- **Executive Dark UI**: Sleek dark aesthetic with a dynamic glowing circular authenticity score dial and interactive on-screen report toggle.
- **Explainable Heuristics**: Generates clear, transparent evidence statements and points rather than arbitrary "AI probabilities".
- **Forensic Dossier Export**: One-click standalone HTML audit report (with print-to-PDF support) and raw JSON export.

---

## Project Structure

```text
TruePic/
├── main.py                  # FastAPI application entry point & static file routing
├── checks/                  # Independent forensic check modules
│   ├── base.py              # Standard CheckResult dataclass
│   ├── sha256_check.py      # Cryptographic file hashes (Weight: 0)
│   ├── c2pa_check.py        # Content Credentials & C2PA manifest (Weight: 25)
│   ├── ai_marker_check.py   # Diffusion parameters & software markers (Weight: 20)
│   ├── camera_check.py      # Camera Make & Model tags (Weight: 12)
│   ├── exposure_check.py    # ISO, Aperture, Shutter Speed, Focal Length (Weight: 12)
│   ├── resolution_check.py  # Diffusion training sizes vs camera sensor aspect (Weight: 7)
│   ├── capture_time_check.py# Original capture timestamp consistency (Weight: 6)
│   ├── makernote_check.py   # Manufacturer proprietary hardware block (Weight: 5)
│   ├── format_check.py      # Container header, extension match & ICC profile (Weight: 5)
│   ├── consistency_check.py # Cross-metadata integrity & coherence (Weight: 5)
│   └── gps_check.py         # Geolocation coordinate presence (Weight: 3)
├── core/
│   ├── context.py           # Single-read parser creating shared ImageContext
│   ├── analyzer.py          # Central pipeline orchestrator (run_analysis)
│   └── scoring.py           # Normalized risk score & confidence calculator
├── static/
│   ├── index.html           # Dark minimalist frontend layout
│   ├── style.css            # Responsive dark theme stylesheet (zero blue)
│   └── app.js               # Client controller, table renderer & report generator
└── tests/                   # Pytest test suite for checks and API
```

---

## 11-Factor Forensic Matrix

The 10 weighted checks total **100 points**. Hashes are informational:

| # | Forensic Check | Module | Target Vector | Weight |
|---|---|---|---|:---:|
| 1 | **SHA-256 / MD5** | `checks/sha256_check.py` | Cryptographic custody integrity | `0` (Info) |
| 2 | **C2PA Credentials** | `checks/c2pa_check.py` | Provenance manifests & AI assertions | `25` |
| 3 | **AI Markers** | `checks/ai_marker_check.py` | Diffusion parameters (Prompt, CFG, Seed, Steps) | `20` |
| 4 | **Camera Make & Model** | `checks/camera_check.py` | Physical camera hardware tags | `12` |
| 5 | **Exposure Parameters** | `checks/exposure_check.py` | Optical physics (ISO, Shutter, Aperture, Focal) | `12` |
| 6 | **Resolution Analysis** | `checks/resolution_check.py` | Diffusion training buckets (e.g. 1024×1024) | `7` |
| 7 | **Capture Timestamp** | `checks/capture_time_check.py` | `DateTimeOriginal` presence & validity | `6` |
| 8 | **MakerNote Block** | `checks/makernote_check.py` | Proprietary camera manufacturer binary IFD | `5` |
| 9 | **Image Format & ICC** | `checks/format_check.py` | MIME match, extension sync, ICC profile | `5` |
| 10 | **Metadata Consistency**| `checks/consistency_check.py` | Stripped metadata vs cross-tag coherence | `5` |
| 11 | **GPS Geolocation** | `checks/gps_check.py` | Real-world GPS coordinates in EXIF | `3` |

---

## Scoring Logic

Each check returns a signal:
- `1.0`: AI-like / synthetic indicator
- `0.5`: Neutral / unknown / stripped metadata
- `0.0`: Real camera provenance indicator

$$\text{Risk Score} = \text{round}\left( \frac{\sum (\text{weight} \times \text{signal})}{\sum \text{active weights}} \times 100 \right)$$

### Risk Scale

| Score | Level | Meaning |
|:---:|:---:|---|
| **0 – 20** | **Low** | Strong physical camera & optical indicators |
| **21 – 40** | **Low-Medium** | Natural characteristics with minor anomalies |
| **41 – 65** | **Inconclusive** | Stripped metadata (e.g., social media uploads) |
| **66 – 85** | **High** | Strong synthetic patterns or generator flags |
| **86 – 100** | **Very High** | Explicit AI markers or C2PA synthetic declaration |

*A direct AI marker or verified synthetic C2PA claim instantly raises the score to **≥ 90**.*

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- Virtual environment (recommended)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-username/TruePic.git
cd TruePic

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Application
```bash
uvicorn main:app --reload --port 8000
```
Open your browser at **`http://localhost:8000`**.

---

## API Endpoints

### `POST /api/analyze`
Uploads an image file (`multipart/form-data`) and returns complete forensic analysis.

**Example Request (cURL):**
```bash
curl -X POST "http://localhost:8000/api/analyze" -F "file=@photo.jpg"
```

**Example Response:**
```json
{
  "filename": "photo.jpg",
  "filesize": 142850,
  "format": "JPEG",
  "dimensions": "4032x3024",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "risk_score": 14,
  "risk_level": "Low",
  "confidence": "High",
  "confidence_percentage": 85,
  "explanation": "Strong physical camera provenance detected with genuine optical exposure parameters.",
  "checks": [...]
}
```

### `GET /api/health`
Health check endpoint reporting API status and total registered checks.

---

## Adding a New Forensic Check

1. Create `checks/your_check.py`:
   ```python
   from checks.base import CheckResult
   from core.context import ImageContext

   KEY = "your_check"
   TITLE = "Your Forensic Check"

   def run(ctx: ImageContext) -> CheckResult:
       return CheckResult(key=KEY, title=TITLE, found=True, signal=0.0, conclusive=True, evidence="Clear evidence.")
   ```
2. Register the module in `checks/__init__.py` inside `CHECK_MODULES`.
3. Set its weight in `CHECK_WEIGHTS` (ensure total active weights equal 100).

---

## License

MIT License. See [LICENSE](LICENSE) for details.
