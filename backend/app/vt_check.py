"""Stage 2c - VirusTotal reputation (existing detections only; we never submit a scan)."""
import base64

import httpx

from . import config
from .cache import TTLCache

_cache = TTLCache(ttl=6 * 3600)
API = "https://www.virustotal.com/api/v3"


def _stats(payload: dict) -> dict:
    s = payload["data"]["attributes"].get("last_analysis_stats", {})
    return {k: int(s.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")}


def check_virustotal(url: str, domain: str) -> dict:
    out = {"enabled": bool(config.VT_API_KEY), "found": False, "source": None, "error": None,
           "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    if not out["enabled"]:
        return out
    cached = _cache.get(url)
    if cached:
        return cached

    headers = {"x-apikey": config.VT_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        with httpx.Client(timeout=6.0) as client:
            r, source = client.get(f"{API}/urls/{url_id}", headers=headers), "url"
            if r.status_code == 404:  # URL never analysed -> fall back to the domain's reputation
                r, source = client.get(f"{API}/domains/{domain}", headers=headers), "domain"
        if r.status_code == 200:
            out.update(_stats(r.json()), found=True, source=source)
            _cache.set(url, out)
        elif r.status_code == 429:
            out["error"] = "rate_limited"
        elif r.status_code != 404:
            out["error"] = f"http_{r.status_code}"
    except Exception as e:  # noqa: BLE001
        out["error"] = type(e).__name__
    return out
