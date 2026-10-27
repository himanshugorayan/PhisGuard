"""Stage 2d - brand-impersonation check (offline string comparison, no network).

Targets the failure mode found in the error analysis: structurally clean domains such as
paaypaal.com or starbuck.com that a purely lexical model cannot flag.
"""
import re

BRANDS = ["paypal", "google", "microsoft", "facebook", "instagram", "whatsapp", "linkedin", "amazon",
          "netflix", "starbucks", "walmart", "dropbox", "spotify", "youtube", "twitter", "outlook",
          "office365", "icloud", "apple", "ebay", "adobe", "coinbase", "binance", "metamask",
          "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "hdfcbank", "icicibank",
          "axisbank", "kotak", "paytm", "phonepe", "flipkart", "irctc", "aadhaar", "digilocker",
          "fedex", "telegram", "steam"]

# genuine domains that merely contain a brand name (extend as needed)
OFFICIAL = {"microsoftonline.com", "googleusercontent.com", "googleapis.com", "amazonaws.com",
            "googlevideo.com", "gstatic.com", "windows.net", "azure.com"}

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _norm(s: str) -> str:
    s = s.lower().translate(_LEET).replace("rn", "m")
    return re.sub(r"(.)\1+", r"\1", s)          # paaypaal -> paypal, gooogle -> gogle


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_lookalike(host: str, domain: str):
    """Return {"kind", "brand", "label", "where"} if the name imitates a known brand, else None."""
    host, domain = host.lower(), domain.lower()
    if domain in OFFICIAL:
        return None
    label = domain.split(".")[0]
    if label in BRANDS:
        return None                                # looks like the brand's own domain; TLD can't be judged
    sub = host[: -len(domain)].strip(".") if host.endswith(domain) else ""

    cands = [("domain", t) for t in [label] + label.split("-")]
    for part in sub.split("."):
        cands += [("subdomain", t) for t in [part] + part.split("-")]

    seen = set()
    for where, t in cands:
        if len(t) < 4 or (where, t) in seen:
            continue
        seen.add((where, t))
        for b in BRANDS:
            if t == b and len(b) >= 5:
                return {"kind": "embedded", "brand": b, "label": t, "where": where}
            if len(b) >= 6 and b in t:
                return {"kind": "embedded", "brand": b, "label": t, "where": where}
            if len(b) >= 6 and abs(len(t) - len(b)) <= 2 and _edit_distance(_norm(t), _norm(b)) <= 1:
                return {"kind": "lookalike", "brand": b, "label": t, "where": where}
    return None
