"""PhisGuard API: lexical ML score -> (DNS | WHOIS | VirusTotal in parallel) -> policy verdict."""
import asyncio
import hashlib
import logging
import time
from collections import defaultdict, deque

import joblib
import pandas as pd
import sklearn
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config
from .dns_check import check_dns
from .features import FEATURE_COLS, extract_features, parse_target, registered_domain
from .policy import decide
from .vt_check import check_virustotal
from .brand_check import brand_lookalike
from .whois_check import check_whois

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("phisguard")

MODEL = joblib.load(config.MODEL_DIR / "phisguard_model.joblib")
log.info("model loaded (scikit-learn %s, %d features)", sklearn.__version__, len(FEATURE_COLS))

app = FastAPI(title="PhisGuard", version="1.0.0",
              description="Pre-navigation phishing triage: lexical ML + DNS + WHOIS + VirusTotal")


class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    deep: bool = True   # False = ML only (fast path, no external calls)


_hits = defaultdict(deque)


def _rate_limit(request: Request):
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() or (request.client.host if request.client else "unknown")
    now, q = time.time(), _hits[ip]
    while q and q[0] < now - 60:
        q.popleft()
    if len(q) >= config.RATE_LIMIT_PER_MIN:
        raise HTTPException(429, "Too many requests - please wait a minute")
    q.append(now)


async def _safe(fn, *args):
    try:
        return await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=config.EXTERNAL_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:  # noqa: BLE001
        return {"error": type(e).__name__}


@app.get("/health")
def health():
    return {"status": "ok", "virustotal_configured": bool(config.VT_API_KEY)}


@app.post("/api/scan")
async def scan(req: ScanRequest, request: Request):
    _rate_limit(request)
    try:
        url, host = parse_target(req.url)
    except ValueError as e:
        raise HTTPException(422, str(e))

    t0 = time.perf_counter()
    features = extract_features(url)
    row = pd.DataFrame([features], columns=FEATURE_COLS)
    prob = float(MODEL.predict_proba(row)[0, 1])    # column 1 = phishing (positive class)
    ml_ms = (time.perf_counter() - t0) * 1000

    domain = registered_domain(host)
    brand = brand_lookalike(host, domain)
    signals, note = {"dns": None, "whois": None, "virustotal": None}, None
    t1 = time.perf_counter()
    if req.deep:
        if prob >= config.SKIP_EXTERNAL_ABOVE:
            note = "ML score already very high - slow external checks skipped (saves latency and API quota)"
        else:
            dns_r, whois_r, vt_r = await asyncio.gather(
                _safe(check_dns, host, domain),
                _safe(check_whois, domain),
                _safe(check_virustotal, url, domain),
            )
            signals = {"dns": dns_r, "whois": whois_r, "virustotal": vt_r}
    ext_ms = (time.perf_counter() - t1) * 1000

    result = decide(prob, config.TAU, signals["dns"], signals["whois"], signals["virustotal"],
                    config.WARN_MARGIN, brand)
    # privacy: log a hash, never the URL itself
    log.info("scan %s verdict=%s p=%.3f deep=%s", hashlib.sha256(url.encode()).hexdigest()[:12],
             result["verdict"], prob, req.deep)

    return {
        "url": url, "host": host, "domain": domain,
        "probability": round(prob, 4), "threshold": config.TAU,
        **result,
        "signals": signals, "brand": brand, "note": note, "features": features,
        "timing_ms": {"ml": round(ml_ms, 1), "external": round(ext_ms, 1)},
    }


# must be last: serves the web UI from "/"
app.mount("/", StaticFiles(directory=config.STATIC_DIR, html=True), name="static")
