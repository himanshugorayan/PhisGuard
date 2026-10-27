"""Stage 1 - static lexical features for ONE URL (no network access).

Produces the 18 features the model was trained on. Column order comes from
models/phisguard_features.joblib, so it cannot drift from training.
"""
import re
from urllib.parse import urlparse

import joblib
import tldextract

from . import config

FEATURE_COLS = joblib.load(config.MODEL_DIR / "phisguard_features.joblib")

# bundled public-suffix snapshot only: never fetches anything at runtime
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I)
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if "://" not in url:
        url = "http://" + url
    return url


def parse_target(raw_url: str):
    """Validate user input. Returns (normalized_url, hostname) or raises ValueError."""
    url = normalize_url(raw_url)
    if len(url) > 2048:
        raise ValueError("URL is too long")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported")
    host = (parsed.hostname or "").lower()
    if not (_HOST_RE.match(host) or _IP_RE.match(host)):
        raise ValueError("Could not find a valid hostname in that URL")
    return url, host


def registered_domain(host: str) -> str:
    """bbc.co.uk for www.bbc.co.uk; the host itself for IPs."""
    return _EXTRACT(host).registered_domain or host


def extract_features(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    n = len(url)

    parts = [p for p in host.split(".") if p]
    tld = parts[-1] if len(parts) > 1 else ""
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    other_special = sum(1 for c in url if not c.isalnum() and c not in "=?&")
    obfuscated = 3 * len(re.findall(r"%[0-9A-F]{2}", url))

    def ratio(x):
        return x / n if n else 0.0

    return {
        "URLLength": n,
        "DomainLength": len(host),
        "IsDomainIP": 1 if _IP_RE.fullmatch(host) else 0,
        "TLDLength": len(tld),
        "NoOfSubDomain": max(len(parts) - 2, 0),
        "HasObfuscation": 1 if obfuscated > 0 else 0,
        "NoOfObfuscatedChar": obfuscated,
        "ObfuscationRatio": ratio(obfuscated),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": ratio(letters),
        "NoOfDegitsInURL": digits,          # sic - dataset spelling
        "DegitRatioInURL": ratio(digits),   # sic
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": other_special,
        "SpacialCharRatioInURL": ratio(other_special),  # sic
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
    }
