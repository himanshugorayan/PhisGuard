
"""Stage 2b - domain registration evidence: age, registrar and dates."""
import datetime as dt
import whois

from .cache import TTLCache

_cache = TTLCache(ttl=24 * 3600)


def _normalize_date(value):
    values = value if isinstance(value, list) else [value]
    dates = []

    for item in values:
        if isinstance(item, dt.datetime):
            if item.tzinfo is not None:
                item = item.astimezone(dt.timezone.utc).replace(tzinfo=None)
            dates.append(item)

    return min(dates) if dates else None


def check_whois(domain: str) -> dict:
    cached = _cache.get(domain)
    if cached:
        return cached

    out = {
        "available": False,
        "not_registered": False,
        "created": None,
        "age_days": None,
        "expires": None,
        "updated": None,
        "registrar": None,
        "error": None,
    }

    try:
        w = whois.whois(domain)

        created = _normalize_date(w.creation_date)
        expires = _normalize_date(w.expiration_date)
        updated = _normalize_date(w.updated_date)

        if created:
            now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
            out.update(
                available=True,
                created=created.date().isoformat(),
                age_days=max((now - created).days, 0),
            )

        if expires:
            out["expires"] = expires.date().isoformat()

        if updated:
            out["updated"] = updated.date().isoformat()

        registrar = w.registrar
        if isinstance(registrar, str):
            out["registrar"] = registrar.strip() or None
        elif isinstance(registrar, list):
            names = [
                name.strip()
                for name in registrar
                if isinstance(name, str) and name.strip()
            ]
            out["registrar"] = ", ".join(names) or None

        _cache.set(domain, out)

    except Exception as e:
        name = type(e).__name__
        if (
            name in ("PywhoisError", "WhoisDomainNotFoundError")
            or "No match" in str(e)
        ):
            out["not_registered"] = True
            _cache.set(domain, out)
        else:
            out["error"] = name

    return out
