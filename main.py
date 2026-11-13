"""
TruePic — Image Authenticity & Forensics Assistant.
FastAPI Application Entry Point.
"""

from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from core.analyzer import run_analysis

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="TruePic — Image Authenticity & Forensics Assistant",
    description="Multi-factor image authenticity and synthetic media forensic analysis engine.",
    version="1.0.0",
)

# CORS middleware for development and testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 30 * 1024 * 1024  # 30 Megabytes limit


@app.get("/")
async def root():
    """Serve the TruePic forensic web interface."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "TruePic API is active. Static frontend missing."}


@app.get("/hello/{name}")
async def say_hello(name: str):
    """Template compatibility endpoint."""
    return {"message": f"Hello {name}"}


@app.get("/api/health")
async def health_check():
    """Return API health status and loaded subsystems."""
    return {
        "status": "healthy",
        "service": "TruePic Forensics API",
        "version": "1.0.0",
        "checks_loaded": 11,
    }


@app.post("/api/analyze")
async def analyze_image(file: UploadFile = File(...)):
    """Analyze an uploaded image through all independent forensic check modules.

    Accepts multipart/form-data image file, executes the full pipeline,
    and returns forensic evidence, weights, risk score, and confidence rating.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No image file provided in upload request.",
        )

    # Read binary bytes up to size limit + 1 byte to detect overflow
    try:
        content = await file.read(MAX_FILE_SIZE + 1024)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded stream: {e}",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size limit of {MAX_FILE_SIZE // (1024 * 1024)} MB.",
        )

    try:
        results = run_analysis(content, file.filename)
        return JSONResponse(status_code=status.HTTP_200_OK, content=results)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal forensic analysis failure: {str(e)}",
        )


# Mount static files directory
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
