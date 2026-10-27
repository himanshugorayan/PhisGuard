
"""All tunables in one place. Override any of them with environment variables."""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"
STATIC_DIR = BASE_DIR / "static"

# Load environment variables from the backend .env file.
load_dotenv(BASE_DIR / ".env")

# Model and policy settings.
TAU = float(os.getenv("PHISGUARD_TAU", "0.19"))
WARN_MARGIN = float(os.getenv("PHISGUARD_WARN_MARGIN", "0.15"))
SKIP_EXTERNAL_ABOVE = float(os.getenv("PHISGUARD_SKIP_ABOVE", "0.9"))

# VirusTotal API key; keep it in .env, never in frontend code.
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

# External service settings.
EXTERNAL_TIMEOUT = float(os.getenv("EXTERNAL_TIMEOUT", "8"))
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "20"))

